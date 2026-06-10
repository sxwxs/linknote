import logging
import os
from datetime import datetime, date
from pathlib import Path
from typing import Optional


class DailyFileHandler(logging.Handler):
    """
    Writes logs to YYYY-mm-dd.log under a directory.

    This is intentionally simple and deterministic (no ".1", no ".2026-02-24")
    to match the requested naming format.
    """

    def __init__(self, log_dir: str | os.PathLike, level: int = logging.NOTSET):
        super().__init__(level=level)
        self._log_dir = Path(log_dir)
        self._log_dir.mkdir(parents=True, exist_ok=True)
        self._current_date: Optional[date] = None
        self._stream = None

    def _ensure_stream(self) -> None:
        today = datetime.now().date()
        if self._stream is not None and self._current_date == today:
            return
        if self._stream is not None:
            try:
                self._stream.close()
            except Exception:
                pass
        self._current_date = today
        path = self._log_dir / f"{today:%Y-%m-%d}.log"
        self._stream = open(path, "a", encoding="utf-8")

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self._ensure_stream()
            msg = self.format(record)
            self._stream.write(msg + "\n")
            self._stream.flush()
        except Exception:
            self.handleError(record)

    def close(self) -> None:
        try:
            if self._stream is not None:
                self._stream.close()
        finally:
            self._stream = None
            super().close()


def get_daily_logger(name: str, log_dir: str | os.PathLike) -> logging.Logger:
    logger = logging.getLogger(name)
    if getattr(logger, "_linknote_daily_configured", False):
        return logger

    handler = DailyFileHandler(log_dir)
    handler.setFormatter(
        logging.Formatter(
            "%(asctime)s - %(levelname)s - %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
        )
    )
    logger.setLevel(logging.INFO)
    logger.addHandler(handler)
    logger.propagate = False
    logger._linknote_daily_configured = True  # type: ignore[attr-defined]
    return logger

