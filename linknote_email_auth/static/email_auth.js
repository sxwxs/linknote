(function () {
  const LOGIN_CHECK_INTERVAL = 2000; // 2 seconds
  const LOGIN_TIMEOUT = 300000; // 5 minutes

  function el(id) {
    return document.getElementById(id);
  }

  function setStatus(text, cls) {
    const div = el("loginStatus");
    if (!div) return;
    div.textContent = text;
    div.className = cls || "";
  }

  async function drawCaptcha() {
    try {
      const response = await fetch("/api/captcha");
      const data = await response.json();
      if (data.success) {
        const img = el("captchaImage");
        if (img) img.src = data.image;
      }
    } catch (e) {
      // Keep UI usable even if CAPTCHA fails.
      console.error("Failed to get CAPTCHA:", e);
    }
  }

  function startEmailLoginCheck() {
    let startTime = Date.now();
    setStatus("Waiting for login...", "");

    if (window.__linknoteEmailAuthInterval) {
      clearInterval(window.__linknoteEmailAuthInterval);
      window.__linknoteEmailAuthInterval = null;
    }

    window.__linknoteEmailAuthInterval = setInterval(async () => {
      try {
        if (Date.now() - startTime > LOGIN_TIMEOUT) {
          clearInterval(window.__linknoteEmailAuthInterval);
          window.__linknoteEmailAuthInterval = null;
          setStatus("Login timeout. Please try again.", "error");
          return;
        }

        const response = await fetch("/api/login/email/status");
        const result = await response.json();

        if (result.success) {
          clearInterval(window.__linknoteEmailAuthInterval);
          window.__linknoteEmailAuthInterval = null;
          const userInfo = result.user_info || { email: result.email };
          window.dispatchEvent(
            new CustomEvent("linknote:login-success", { detail: { userInfo } })
          );
        } else if (result.status === "pending") {
          setStatus(`Waiting for login (sent to ${result.email})...`, "");
        }
      } catch (e) {
        console.error("Failed to check email login status:", e);
      }
    }, LOGIN_CHECK_INTERVAL);
  }

  async function requestEmailLogin() {
    try {
      const emailInput = el("loginEmail");
      const captchaInput = el("captchaInput");
      const email = (emailInput && emailInput.value ? emailInput.value : "").trim();
      const captcha = (captchaInput && captchaInput.value ? captchaInput.value : "").trim();

      if (!email) throw new Error("Email is required");

      setStatus("Sending login email...", "");

      const response = await fetch("/api/login/email/request", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, captcha }),
      });

      const result = await response.json();
      if (!result.success) throw new Error(result.error || "Request failed");

      setStatus("Login email sent! Please check your inbox.", "success");
      if (emailInput) emailInput.value = "";
      startEmailLoginCheck();
    } catch (e) {
      setStatus(`Login failed: ${e.message || e}`, "error");
    }
  }

  function init() {
    const refreshBtn = el("refreshCaptcha");
    if (refreshBtn) {
      refreshBtn.addEventListener("click", () => {
        drawCaptcha();
        const captchaInput = el("captchaInput");
        if (captchaInput) captchaInput.value = "";
      });
    }

    const sendBtn = el("sendLoginEmail");
    if (sendBtn) sendBtn.addEventListener("click", () => requestEmailLogin());

    const loginEmailInput = el("loginEmail");
    const captchaInput = el("captchaInput");
    if (loginEmailInput) {
      loginEmailInput.addEventListener("keypress", function (e) {
        if (e.key === "Enter") {
          e.preventDefault();
          if (captchaInput && captchaInput.value.trim() !== "") {
            sendBtn && sendBtn.click();
          }
        }
      });
    }
    if (captchaInput) {
      captchaInput.addEventListener("keypress", function (e) {
        if (e.key === "Enter") {
          e.preventDefault();
          if (loginEmailInput && loginEmailInput.value.trim() !== "") {
            sendBtn && sendBtn.click();
          }
        }
      });
    }
  }

  window.LinknoteEmailAuth = {
    init,
    drawCaptcha,
    requestEmailLogin,
    startEmailLoginCheck,
  };

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();

