"""
SMTP alert delivery.

Never raises. If SMTP is not configured, the alert is logged as skipped
and the caller continues — alert delivery must not interfere with packet
analysis. The return value indicates whether the message was accepted by
the SMTP server.
"""

from __future__ import annotations

import os
import smtplib
from email.mime.text import MIMEText
from email.utils import formatdate

import dotenv

from logging_config import get_logger

dotenv.load_dotenv()

SMTP_HOST = os.getenv("SMTP_HOST")
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")
SMTP_FROM = os.getenv("SMTP_FROM") or SMTP_USER

_PORT_RAW = (os.getenv("SMTP_PORT") or "").strip()
try:
    SMTP_PORT = int(_PORT_RAW) if _PORT_RAW else None
except ValueError:
    SMTP_PORT = None

logger = get_logger(__name__)

RECIPIENTS = [
    addr.strip()
    for addr in (os.getenv("ALERT_RECIPIENTS") or "").split(",")
    if addr.strip()
]

# Logged at most once per process so a burst of alerts with a broken
# config does not flood the log.
_config_warned = False


def _missing_config() -> str | None:
    """Return a short description of what's missing, or None if OK."""
    missing: list[str] = []
    if not SMTP_HOST:
        missing.append("SMTP_HOST")
    if SMTP_PORT is None:
        missing.append("SMTP_PORT (must be an integer)")
    if not SMTP_USER:
        missing.append("SMTP_USER")
    if not SMTP_PASSWORD:
        missing.append("SMTP_PASSWORD")
    if not SMTP_FROM:
        missing.append("SMTP_FROM")
    if not RECIPIENTS:
        missing.append("ALERT_RECIPIENTS")
    return ", ".join(missing) if missing else None


def send_alert(subject: str, message: str) -> bool:
    """
    Send one alert email. Returns True if the SMTP server accepted it,
    False on any failure including missing configuration.

    This function never raises. The caller cannot be broken by an alert
    delivery problem — that is a hard requirement for a hot path like
    packet analysis.
    """
    global _config_warned

    missing = _missing_config()
    if missing:
        if not _config_warned:
            logger.warning(
                "Email alerts are disabled: %s not set. "
                "Configure them in .env to enable alerting.",
                missing,
            )
            _config_warned = True
        return False

    msg = MIMEText(message, "plain", "utf-8")
    msg["Subject"] = subject
    msg["From"] = SMTP_FROM
    msg["To"] = ", ".join(RECIPIENTS)
    msg["Date"] = formatdate(localtime=True)

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(SMTP_FROM, RECIPIENTS, msg.as_string())
        logger.info("Alert sent: %s (%d recipient(s))", subject, len(RECIPIENTS))
        return True
    except Exception:
        logger.error("Email alert failed (subject=%s)", subject, exc_info=True)
        return False