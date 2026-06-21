import os
import smtplib
from email.mime.text import MIMEText
import dotenv

from logging_config import get_logger

dotenv.load_dotenv()

SMTP_HOST = os.getenv("SMTP_HOST")
SMTP_PORT = os.getenv("SMTP_PORT")
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")

logger = get_logger(__name__)

# For production, prefer configuring this via environment or DB.
RECIPIENTS = [addr.strip() for addr in (os.getenv("ALERT_RECIPIENTS") or "").split(",") if addr.strip()] or [
    "kamalxan@gmail.com",
]


def _ensure_smtp_config():
    if not SMTP_HOST or not SMTP_PORT or not SMTP_USER or not SMTP_PASSWORD:
        raise RuntimeError("SMTP is not fully configured for alerting")


def send_alert(subject, message):
    _ensure_smtp_config()

    msg = MIMEText(message)
    msg["Subject"] = subject
    msg["From"] = SMTP_USER
    msg["To"] = ", ".join(RECIPIENTS)

    try:
        with smtplib.SMTP(SMTP_HOST, int(SMTP_PORT)) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(SMTP_USER, RECIPIENTS, msg.as_string())
    except Exception:
        logger.error("Email alert failed (subject=%s)", subject, exc_info=True)
