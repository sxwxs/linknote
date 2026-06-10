import base64
import re
import secrets
import smtplib
import time
from dataclasses import dataclass
from email.mime.text import MIMEText
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from captcha.image import ImageCaptcha
from flask import Blueprint, current_app, jsonify, redirect, request, session

from .daily_log import get_daily_logger

# Token store is intentionally in-memory; LinkNote is typically single-process.
_email_tokens: Dict[str, Dict[str, Any]] = {}


_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(x).strip() for x in value if str(x).strip()]
    if isinstance(value, str):
        return [x.strip() for x in value.split(",") if x.strip()]
    return [str(value).strip()] if str(value).strip() else []


def _is_valid_email(email: str) -> bool:
    return bool(_EMAIL_RE.match(email.strip()))


@dataclass(frozen=True)
class EmailAuthConfig:
    enabled: bool
    allow_anyone: bool
    allowed_emails: list[str]
    require_captcha: bool
    captcha_ttl_seconds: int
    token_ttl_seconds: int
    base_url: Optional[str]
    redirect_path: str
    smtp_server: str
    smtp_port: int
    smtp_account: str
    smtp_password: str
    smtp_use_ssl: bool
    smtp_starttls: bool
    login_log_dir: Optional[str]
    email_log_dir: Optional[str]


def _load_cfg() -> Tuple[bool, Optional[EmailAuthConfig], str]:
    """
    Returns: (ok, cfg|None, error_message)
    """
    if not current_app.config.get("LOGIN_ENABLED", False):
        return False, None, "Login is not enabled"

    login_cfg = current_app.config.get("LOGIN_CONFIG") or {}
    if login_cfg.get("type") != "email":
        return False, None, "Email login is not enabled"

    email_cfg = (login_cfg.get("email") or {}) if isinstance(login_cfg, dict) else {}
    if not email_cfg.get("enabled", False):
        return False, None, "Email login is not enabled"

    allow_anyone = bool(email_cfg.get("allow_anyone", False))
    allowed_emails = _as_list(email_cfg.get("allowed_emails"))
    # Back-compat: if restricted and allowlist is empty, use admin_email (if set).
    if not allow_anyone and not allowed_emails:
        allowed_emails = _as_list(email_cfg.get("admin_email"))

    token_ttl_seconds = int(email_cfg.get("token_ttl_seconds", 15 * 60))

    captcha_cfg = email_cfg.get("captcha") or {}
    require_captcha = bool(email_cfg.get("require_captcha", True))
    captcha_ttl_seconds = int(
        captcha_cfg.get("ttl_seconds", email_cfg.get("captcha_ttl_seconds", 5 * 60))
    )

    smtp_server = str(email_cfg.get("smtp_server", "")).strip()
    smtp_port = int(email_cfg.get("smtp_port", 465))
    smtp_account = str(email_cfg.get("account", "")).strip()
    smtp_password = str(email_cfg.get("password", "")).strip()

    if not smtp_server or not smtp_account or not smtp_password:
        return False, None, "Email login is misconfigured (missing SMTP settings)"

    smtp_use_ssl = bool(email_cfg.get("smtp_use_ssl", smtp_port == 465))
    smtp_starttls = bool(email_cfg.get("smtp_starttls", not smtp_use_ssl))

    base_url = email_cfg.get("base_url")
    if isinstance(base_url, str):
        base_url = base_url.strip() or None
    else:
        base_url = None

    redirect_path = str(email_cfg.get("redirect_path", "/static/index.html"))

    logs_cfg = email_cfg.get("logs") or {}
    login_log_dir = email_cfg.get("login_log_dir") or logs_cfg.get("login_dir")
    email_log_dir = email_cfg.get("email_log_dir") or logs_cfg.get("email_dir")

    cfg = EmailAuthConfig(
        enabled=True,
        allow_anyone=allow_anyone,
        allowed_emails=[e.lower() for e in allowed_emails],
        require_captcha=require_captcha,
        captcha_ttl_seconds=captcha_ttl_seconds,
        token_ttl_seconds=token_ttl_seconds,
        base_url=base_url,
        redirect_path=redirect_path,
        smtp_server=smtp_server,
        smtp_port=smtp_port,
        smtp_account=smtp_account,
        smtp_password=smtp_password,
        smtp_use_ssl=smtp_use_ssl,
        smtp_starttls=smtp_starttls,
        login_log_dir=str(login_log_dir) if login_log_dir else None,
        email_log_dir=str(email_log_dir) if email_log_dir else None,
    )
    return True, cfg, ""


def _log_email(cfg: EmailAuthConfig, message: str) -> None:
    if not cfg.email_log_dir:
        return
    get_daily_logger("linknote_email_auth.email", cfg.email_log_dir).info(message)


def _log_login(cfg: EmailAuthConfig, message: str) -> None:
    if not cfg.login_log_dir:
        return
    get_daily_logger("linknote_email_auth.login", cfg.login_log_dir).info(message)


def _send_login_email(cfg: EmailAuthConfig, recipient: str, login_url: str) -> None:
    body = f"""
Hello,

Click the following link to log in:

{login_url}

This link will expire in {cfg.token_ttl_seconds // 60} minutes.

If you didn't request this login, please ignore this email.
""".strip()

    msg = MIMEText(body, "plain", "utf-8")
    msg["From"] = cfg.smtp_account
    msg["To"] = recipient
    msg["Subject"] = "Login Link"

    if cfg.smtp_use_ssl:
        smtp = smtplib.SMTP_SSL(cfg.smtp_server, cfg.smtp_port)
    else:
        smtp = smtplib.SMTP(cfg.smtp_server, cfg.smtp_port)
    try:
        smtp.ehlo()
        if cfg.smtp_starttls:
            smtp.starttls()
            smtp.ehlo()
        smtp.login(cfg.smtp_account, cfg.smtp_password)
        smtp.sendmail(cfg.smtp_account, [recipient], msg.as_string())
    finally:
        try:
            smtp.quit()
        except Exception:
            pass


def _cleanup_expired(now: float) -> None:
    # Bound cleanup cost; called on request/status/verify paths only.
    to_delete = []
    for token, data in _email_tokens.items():
        if now - float(data.get("created_at", 0)) > float(data.get("ttl", 0)):
            to_delete.append(token)
    for token in to_delete:
        _email_tokens.pop(token, None)


def create_email_auth_blueprint() -> Blueprint:
    bp = Blueprint(
        "linknote_email_auth",
        __name__,
        static_folder="static",
        static_url_path="/static/linknote_email_auth",
    )

    @bp.get("/api/captcha")
    def get_captcha():
        ok, cfg, err = _load_cfg()
        if not ok or cfg is None:
            return jsonify({"success": False, "error": err}), 400
        if not cfg.require_captcha:
            return jsonify({"success": False, "error": "CAPTCHA is disabled"}), 400

        image = ImageCaptcha(width=280, height=90)
        chars = "23456789ABCDEFGHIJKMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        captcha_text = "".join(secrets.choice(chars) for _ in range(6))
        session["captcha"] = captcha_text
        session["captcha_time"] = time.time()

        img_bytes = image.generate(captcha_text)
        img_base64 = base64.b64encode(img_bytes.getvalue()).decode("ascii")
        return jsonify({"success": True, "image": f"data:image/png;base64,{img_base64}"})

    @bp.post("/api/login/verify-captcha")
    def verify_captcha():
        captcha = (request.json or {}).get("captcha")
        if not captcha:
            return jsonify({"success": False, "error": "CAPTCHA is required"}), 400
        if captcha.lower() == str(session.get("captcha", "")).lower():
            return jsonify({"success": True})
        return jsonify({"success": False, "error": "Invalid CAPTCHA"}), 400

    @bp.post("/api/login/email/request")
    def request_email_login():
        ok, cfg, err = _load_cfg()
        if not ok or cfg is None:
            return jsonify({"success": False, "error": err}), 400

        data = request.json or {}
        email = str(data.get("email", "")).strip()
        captcha = str(data.get("captcha", "")).strip()

        if not email:
            return jsonify({"success": False, "error": "Email is required"}), 400
        if not _is_valid_email(email):
            return jsonify({"success": False, "error": "Invalid email"}), 400

        if not cfg.allow_anyone and email.lower() not in set(cfg.allowed_emails):
            return jsonify({"success": False, "error": "Email is not allowed"}), 403

        if cfg.require_captcha:
            if time.time() - float(session.get("captcha_time", 0)) > cfg.captcha_ttl_seconds:
                return jsonify({"success": False, "error": "CAPTCHA expired"}), 400
            if not captcha or captcha.lower() != str(session.get("captcha", "")).lower():
                return jsonify({"success": False, "error": "Invalid CAPTCHA"}), 400
            session["captcha"] = None
            session["captcha_time"] = 0

        token = secrets.token_urlsafe(32)
        now = time.time()
        _cleanup_expired(now)
        _email_tokens[token] = {"email": email, "status": "pending", "created_at": now, "ttl": cfg.token_ttl_seconds}

        base_url = cfg.base_url or request.url_root.rstrip("/")
        login_url = f"{base_url}/api/login/email/verify?token={token}"
        try:
            _send_login_email(cfg, email, login_url)
        except Exception as e:
            _email_tokens.pop(token, None)
            _log_email(cfg, f"EMAIL_SEND_FAILED email={email} ip={request.remote_addr} ua={request.headers.get('User-Agent','')} err={e!r}")
            return jsonify({"success": False, "error": "Failed to send login email"}), 500

        session["token"] = token  # back-compat with LinkNote's current session key
        _log_email(cfg, f"EMAIL_SENT email={email} ip={request.remote_addr} ua={request.headers.get('User-Agent','')}")
        return jsonify({"success": True, "message": "Login email sent"})

    @bp.get("/api/login/email/status")
    def email_login_status():
        ok, cfg, err = _load_cfg()
        if not ok or cfg is None:
            return jsonify({"success": False, "error": err}), 400

        token = session.get("token")
        if not token or token not in _email_tokens:
            return jsonify({"success": False, "error": "No active login request"}), 400

        now = time.time()
        _cleanup_expired(now)
        token_data = _email_tokens.get(token)
        if not token_data:
            session.pop("token", None)
            return jsonify({"success": False, "error": "Login request expired"}), 400

        if token_data["status"] == "pending":
            return jsonify({"success": False, "status": "pending", "email": token_data["email"]})

        if token_data["status"] == "success":
            email = token_data["email"]
            # Store user info in session (LinkNote consumes this for access control).
            session["user_info"] = {"email": email}
            _email_tokens.pop(token, None)
            session.pop("token", None)
            _log_login(cfg, f"LOGIN_SUCCESS email={email} ip={request.remote_addr} ua={request.headers.get('User-Agent','')}")
            return jsonify({"success": True, "status": "success", "email": email})

        return jsonify({"success": False, "error": "Invalid login state"}), 500

    @bp.get("/api/login/email/verify")
    def verify_email_login():
        ok, cfg, err = _load_cfg()
        if not ok or cfg is None:
            return jsonify({"success": False, "error": err}), 400

        token = request.args.get("token")
        if not token or token not in _email_tokens:
            return jsonify({"success": False, "error": "Invalid token"}), 400

        now = time.time()
        _cleanup_expired(now)
        token_data = _email_tokens.get(token)
        if not token_data:
            return jsonify({"success": False, "error": "Token expired"}), 400

        token_data["status"] = "success"
        # If the same browser session requested this token, log in immediately.
        if session.get("token") == token:
            email = token_data["email"]
            session["user_info"] = {"email": email}
            _email_tokens.pop(token, None)
            session.pop("token", None)
            _log_login(cfg, f"LOGIN_SUCCESS email={email} ip={request.remote_addr} ua={request.headers.get('User-Agent','')}")
        return redirect(cfg.redirect_path)

    return bp
