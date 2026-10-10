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
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
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


def send_alert(subject, message, html=None, attachments=None):
    """
    Send one alert email. `html` optionally supplies a rich-text alternative;
    `attachments` is a list of (filename, mime_type, bytes) tuples.
    """
    ...
    if html or attachments:
        msg = MIMEMultipart("mixed")
        alt = MIMEMultipart("alternative")
        alt.attach(MIMEText(message, "plain", "utf-8"))
        if html:
            alt.attach(MIMEText(html, "html", "utf-8"))
        msg.attach(alt)
        for name, mime, data in attachments or []:
            part = MIMEBase(*mime.split("/", 1))
            part.set_payload(data)
            encoders.encode_base64(part)
            part.add_header("Content-Disposition", "attachment", filename=name)
            msg.attach(part)
    else:
        msg = MIMEText(message, "plain", "utf-8")

    msg["Subject"] = subject
    msg["From"] = SMTP_FROM
    msg["To"] = ", ".join(RECIPIENTS)