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
SMTP_FROM = os.getenv("SMTP_FROM") or SMTP_USER

logger = get_logger(__name__)

RECIPIENTS = [
    addr.strip()
    for addr in (os.getenv("ALERT_RECIPIENTS") or "").split(",")
    if addr.strip()
]


def _ensure_recipients_configured():
    if not RECIPIENTS:
        raise RuntimeError(
            "ALERT_RECIPIENTS is not set. Configure it in .env to enable email alerts."
        )


def _ensure_smtp_config():
    if not SMTP_HOST or not SMTP_PORT or not SMTP_USER or not SMTP_PASSWORD:
        raise RuntimeError("SMTP is not fully configured for alerting")


def send_alert(subject, message):
    _ensure_smtp_config()
    _ensure_recipients_configured()

    msg = MIMEText(message)
    msg["Subject"] = subject
    msg["From"] = SMTP_FROM
    msg["To"] = ", ".join(RECIPIENTS)

    try:
        with smtplib.SMTP(SMTP_HOST, int(SMTP_PORT), timeout=10) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(SMTP_FROM, RECIPIENTS, msg.as_string())
        logger.info("Alert sent: %s (%d recipient(s))", subject, len(RECIPIENTS))
    except Exception:
        logger.error("Email alert failed (subject=%s)", subject, exc_info=True)
