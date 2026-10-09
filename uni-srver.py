from flask import Flask, request, redirect, render_template, send_file, session, jsonify, abort, Response
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin, current_user
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.utils import secure_filename
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.exceptions import Forbidden
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from argon2.low_level import Type
from datetime import timedelta, datetime, timezone
from threading import Thread
import pyotp
import qrcode
import io
import os
import secrets
from functools import wraps
import smtplib
import dotenv
from email.message import EmailMessage
from PIL import Image
import re
import json
import hashlib
from storage.memory_store import stats, logs, sync_stats_from_persistence
from storage.mysql_store import (
    aggregate_log_stats,
    aggregate_traffic_timeseries,
    query_logs,
    cleanup_old_logs,
)
from storage.analytics import (
    get_heatmap,
    get_periodic_patterns,
    get_recurring_actors,
    get_top_threats,
    get_weekly_summary,
)
from storage.audit import audit, cleanup_retention as audit_cleanup, distinct_actions as audit_actions, query_audit, stats_since as audit_stats
from intelligence.sensor_auth import NonceTracker, verify_request
from storage.persistence import (
    apply_telemetry_stats,
    init_persistence,
    load_statistics_for_api,
)
from ids.metrics import export_prometheus
from ids.websocket_updates import sse_stream, broadcast
from storage.db import get_session
from storage.models import User as DbUser
import time

dotenv.load_dotenv()

required_vars = ["FLASK_SECRET"]
smtp_vars = ["SMTP_HOST", "SMTP_PORT", "SMTP_USER", "SMTP_PASSWORD", "SMTP_FROM"]

missing = [var for var in required_vars if not os.environ.get(var)]
if missing:
    raise RuntimeError(f"Missing environment variables: {', '.join(missing)}")

# SMTP is optional: only required when email OTP / alert email is used.
for var in required_vars + smtp_vars:
    globals()[var] = os.environ.get(var)

app = Flask(__name__)

# NOTE: SECRET_KEY must come from FLASK_SECRET (not a fresh secrets.token_hex()
# generated at import time) so that sessions/CSRF tokens stay valid across
# process restarts and across multiple worker processes in production.
_use_ssl = (os.getenv("WEB_UI_SSL", "true") or "true").lower() == "true"
app.config.update(
    SESSION_COOKIE_NAME="__Host-ids_session",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=_use_ssl,
    SESSION_COOKIE_SAMESITE="Strict",
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=60),
    SESSION_REFRESH_EACH_REQUEST=True,
    MAX_CONTENT_LENGTH=2 * 1024 * 1024,
    SECRET_KEY=FLASK_SECRET,
)

# --- Reverse proxy handling -------------------------------------------------
# Trust X-Forwarded-* only if TRUSTED_PROXIES > 0.
# 0 = directly exposed, 1 = single reverse proxy, etc.
_TRUSTED_PROXIES = int(os.getenv("TRUSTED_PROXIES", "0") or "0")
if _TRUSTED_PROXIES > 0:
    app.wsgi_app = ProxyFix(
        app.wsgi_app,
        x_for=_TRUSTED_PROXIES,
        x_proto=_TRUSTED_PROXIES,
        x_host=_TRUSTED_PROXIES,
    )

# Enterprise-tuned rate limits. The default covers aggregate traffic from
# any single source — loopback and authenticated sessions are exempted
# below because:
#   1. The dashboard polls /ids/health every 5s and /ids/stats every 10s
#      from the browser, which alone is ~1200 requests/hour per open tab.
#   2. Prometheus scrapes /metrics on its own schedule.
#   3. An authenticated SOC analyst is a trusted principal — throttling
#      them protects nothing and generates log noise.
# Per-endpoint limits (login, MFA, admin) still apply because they are
# registered with explicit @limiter.limit(...) decorators below.
_DEFAULT_HOURLY = int(os.getenv("RATELIMIT_DEFAULT_HOURLY", "5000") or "5000")
_DEFAULT_DAILY = int(os.getenv("RATELIMIT_DEFAULT_DAILY", "50000") or "50000")

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[f"{_DEFAULT_DAILY} per day", f"{_DEFAULT_HOURLY} per hour"],
)

# Loopback only. Do NOT include proxy IPs here.
ALLOWED_IPS = {"127.0.0.1", "::1"}


@limiter.request_filter
def whitelist_trusted():
    """
    Exempt loopback and authenticated sessions from the *default* limits.
    Per-endpoint @limiter.limit decorators still apply, so login and MFA
    remain throttled.
    """
    if request.remote_addr in ALLOWED_IPS:
        return True
    try:
        return bool(current_user.is_authenticated)
    except Exception:
        return False


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.session_protection = "strong"


@login_manager.unauthorized_handler
def _unauthorized():
    audit(
        "auth.unauthorized",
        outcome="denied",
        detail={
            "path": request.path,
            "method": request.method,
            "endpoint": request.endpoint,
        },
    )
    if request.path.startswith(("/ids/", "/admin/api/")):
        return api_error("Authentication required", status_code=401, code="unauthorized")
    return redirect(login_manager.login_view)


@app.errorhandler(Forbidden)
def _forbidden(e):
    try:
        role = (
            getattr(current_user, "role", None)
            if getattr(current_user, "is_authenticated", False)
            else None
        )
    except Exception:
        role = None

    audit(
        "auth.forbidden",
        outcome="denied",
        detail={
            "path": request.path,
            "method": request.method,
            "endpoint": request.endpoint,
            "role": role,
        },
    )
    if request.path.startswith(("/ids/", "/admin/api/")):
        return api_error("Forbidden", status_code=403, code="forbidden")
    return e


@app.errorhandler(429)
def _rate_limited(e):
    audit(
        "rate_limit.exceeded",
        outcome="denied",
        detail={
            "path": request.path,
            "method": request.method,
            "endpoint": request.endpoint,
        },
    )
    return e


@app.errorhandler(500)
def _internal_error(e):
    audit(
        "server.error",
        outcome="failure",
        detail={
            "path": request.path,
            "method": request.method,
            "endpoint": request.endpoint,
        },
    )
    if request.path.startswith(("/ids/", "/admin/api/", "/analytics/", "/audit/")):
        return api_error("Internal error", status_code=500, code="internal_error")
    return e


ph = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=2,
    type=Type.ID,
)

# Shared bounds so every entry point that hashes/verifies a password agrees
# on the same limits.
MAX_USERNAME_LEN = 30
MAX_PASSWORD_LEN = 64
USERNAME_RE = re.compile(r"^[a-zA-Z0-9_-]{3,30}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

# Fixed dummy hash used to burn roughly the same amount of Argon2 time on
# "unknown username" as on "wrong password", so response timing can't be
# used to enumerate valid usernames.
_DUMMY_PASSWORD_HASH = ph.hash(secrets.token_hex(32))


def utcnow():
    """Naive UTC now — replaces deprecated datetime.utcnow()."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _pwd_fingerprint(password_hash: str) -> str:
    """Session binding: derived from the password hash, so any password
    change (self or admin) invalidates existing sessions automatically."""
    return hashlib.sha256(password_hash.encode("utf-8")).hexdigest()[:32]


def _otp_matches(supplied: str, stored: str | None) -> bool:
    if not stored or not supplied:
        return False
    return secrets.compare_digest(supplied, stored)


def _record_password_failure(user_id: int) -> None:
    """Increment failed_attempts and lock after 5 (mirrors /login)."""
    s = get_session()
    try:
        u = s.get(DbUser, int(user_id))
        if not u:
            return
        failed = int(u.failed_attempts or 0) + 1
        if failed >= 5:
            u.locked_until = (utcnow() + timedelta(minutes=15)).isoformat()
        u.failed_attempts = failed
        s.commit()
    finally:
        s.close()


def _check_account_locked(user_row) -> bool:
    locked_until = getattr(user_row, "locked_until", None)
    if not locked_until:
        return False
    try:
        return utcnow() < datetime.fromisoformat(locked_until)
    except Exception:
        return False


def _equalize_auth_timing(password: str) -> None:
    try:
        ph.verify(_DUMMY_PASSWORD_HASH, password)
    except Exception:
        pass


@app.before_request
def strict_request_validation():
    te = request.headers.get("Transfer-Encoding")
    cl = request.headers.get("Content-Length")

    def _reject(reason, status, **extra):
        audit(
            "request.rejected",
            outcome="denied",
            detail={
                "reason": reason,
                "path": request.path,
                "method": request.method,
                **extra,
            },
        )
        return {"error": "bad request"}, status

    if te and cl:
        return _reject("te_and_cl", 400)

    if te and te.lower() != "chunked":
        return _reject("bad_te", 400, te=te)

    if cl:
        try:
            if int(cl) <= 0 or int(cl) > app.config["MAX_CONTENT_LENGTH"]:
                return _reject("invalid_length", 413, content_length=cl)
        except ValueError:
            return _reject("non_numeric_content_length", 400, content_length=cl)

    if request.method in ("POST", "PUT", "PATCH"):
        if not request.content_type:
            return _reject("missing_content_type", 400)

    return None


@app.after_request
def secure_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "script-src 'self' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:"
    )
    response.headers["Permissions-Policy"] = (
        "geolocation=(), microphone=(), camera=(), "
        "payment=(), usb=(), magnetometer=(), gyroscope=()"
    )
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    response.headers["X-Permitted-Cross-Domain-Policies"] = "none"
    return response


def generate_csrf_token():
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token


def verify_csrf():
    if request.method not in ("POST", "PUT", "DELETE", "PATCH"):
        return

    session_token = session.get("_csrf_token")
    form_token = request.form.get("csrf_token")
    header_token = request.headers.get("X-CSRF-Token")

    candidate = form_token or header_token
    if not session_token or not candidate or not secrets.compare_digest(session_token, candidate):
        audit(
            "csrf.failure",
            outcome="denied",
            detail={
                "path": request.path,
                "method": request.method,
                "had_session_token": bool(session_token),
                "had_candidate": bool(candidate),
            },
        )
        abort(400, description="Invalid CSRF token")


def csrf_protect(view_func):
    @wraps(view_func)
    def wrapped_view(*args, **kwargs):
        verify_csrf()
        return view_func(*args, **kwargs)

    return wrapped_view


app.jinja_env.globals["csrf_token"] = generate_csrf_token


def api_ok(data=None, *, meta=None, status_code: int = 200):
    return jsonify({"success": True, "data": data, "error": None, "meta": meta or {}}), status_code


def api_error(message: str, *, status_code: int = 400, code: str | None = None, meta=None):
    return (
        jsonify(
            {
                "success": False,
                "data": None,
                "error": {"message": message, "code": code or "error"},
                "meta": meta or {},
            }
        ),
        status_code,
    )


def get_db():
    """
    Deprecated helper kept only for backward compatibility.
    New code should use SQLAlchemy sessions via get_session().
    """
    return get_session()


class User(UserMixin):
    def __init__(self, id, username, password_hash, role, totp_secret, totp_enabled):
        self.id = id
        self.username = username
        self.password_hash = password_hash
        self.role = (role or "soc").lower()
        self.totp_secret = totp_secret
        self.totp_enabled = bool(totp_enabled)


@login_manager.user_loader
def load_user(user_id):
    s = get_session()
    try:
        row = s.get(DbUser, int(user_id))
        if not row:
            return None

        # Password change / admin reset → hash differs → kill session.
        stored_fp = session.get("pwd_fp")
        if not stored_fp or stored_fp != _pwd_fingerprint(row.password_hash):
            session.clear()
            return None

        # Account locked → kill session immediately.
        if row.locked_until:
            try:
                if utcnow() < datetime.fromisoformat(row.locked_until):
                    session.clear()
                    return None
            except Exception:
                pass

        return User(
            row.id, row.username, row.password_hash,
            row.role, row.totp_secret, row.totp_enabled,
        )
    finally:
        s.close()


def role_required(*allowed_roles: str):
    allowed = {r.lower() for r in allowed_roles}

    def decorator(view_func):
        @wraps(view_func)
        def wrapped(*args, **kwargs):
            if not current_user.is_authenticated:
                return login_manager.unauthorized()
            if getattr(current_user, "role", "soc").lower() not in allowed:
                abort(403)
            return view_func(*args, **kwargs)

        return wrapped

    return decorator

def _is_ssl_proc_running() -> bool:
    """
    Best-effort check: is an SSL interceptor process listening on the
    configured port? Used by /ssl/api/status.
    """
    import socket

    port = int(os.getenv("SSL_INTERCEPT_PORT", "8443") or "8443")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.4)
            s.connect(("127.0.0.1", port))
        return True
    except OSError:
        return False

def start_retention_worker():
    while True:
        try:
            deleted = cleanup_old_logs(days=7)
            if deleted:
                import logging
                logging.getLogger(__name__).info("Retention cleanup removed %d packet log rows", deleted)
            audit_deleted = audit_cleanup()
            if audit_deleted:
                import logging
                logging.getLogger(__name__).info("Retention cleanup removed %d audit rows", audit_deleted)
        except Exception:
            import logging
            logging.getLogger(__name__).error("Retention worker failed", exc_info=True)
        time.sleep(3600)

def start_analytics_worker_thread():
    """Kick off the hourly analytics aggregation loop in a daemon thread."""
    from storage.analytics import start_analytics_worker as _run
    Thread(target=_run, daemon=True, name="analytics-worker").start()

def mask_email(email_value: str) -> str:
    if not email_value or "@" not in email_value:
        return email_value or ""
    name, domain = email_value.split("@", 1)
    if not name:
        return "***@" + domain
    visible = name[0]
    return f"{visible}***@{domain}"


def _clamav_scan_clean(data: bytes) -> bool:
    """
    Best-effort ClamAV scan of an uploaded file's bytes.

    Returns False only when the daemon actively reports the content as
    infected. If clamd is unreachable/unconfigured we fail open (allow the
    upload) but log it loudly.
    """
    import logging

    try:
        import pyclamd
    except ImportError:
        logging.getLogger(__name__).warning(
            "pyclamd not installed; skipping avatar malware scan"
        )
        return True

    try:
        cd = pyclamd.ClamdUnixSocket()
        if not cd.ping():
            cd = pyclamd.ClamdNetworkSocket()
            cd.ping()
    except Exception:
        logging.getLogger(__name__).warning(
            "ClamAV daemon unreachable; skipping avatar malware scan"
        )
        return True

    try:
        result = cd.scan_stream(data)
    except Exception:
        logging.getLogger(__name__).warning(
            "ClamAV scan failed; skipping avatar malware scan", exc_info=True
        )
        return True

    if result is not None:
        logging.getLogger(__name__).warning("ClamAV flagged an uploaded avatar: %r", result)
    return result is None


def send_email_otp(to_email: str, code: str, purpose: str = "Login verification") -> None:
    host = SMTP_HOST
    try:
        port = int(SMTP_PORT)
    except (TypeError, ValueError):
        raise RuntimeError("SMTP_PORT must be an integer")
    user = SMTP_USER
    password = SMTP_PASSWORD
    sender = SMTP_FROM

    if not host or not user or not password or not sender:
        raise RuntimeError("SMTP is not configured")

    msg = EmailMessage()
    msg["Subject"] = f"{purpose} code"
    msg["From"] = sender
    msg["To"] = to_email
    msg.set_content(
        f"Your verification code is: {code}\n\n"
        "This code will expire in a few minutes. "
        "If you did not request this, you can ignore this email."
    )

    with smtplib.SMTP(host, port, timeout=10) as smtp:
        smtp.starttls()
        smtp.login(user, password)
        smtp.send_message(msg)


@app.route("/")
def index():
    if current_user.is_authenticated:
        return redirect("/dashboard")
    return redirect("/login")


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
@csrf_protect
def login():
    if request.method == "GET":
        return render_template("login.html")

    def render_login_error(message, status_code=401):
        return render_template("login.html", error=message), status_code

    username = request.form.get("username")
    username = (username or "").strip()

    password = request.form.get("password") or ""

    if len(username) > MAX_USERNAME_LEN or len(password) > MAX_PASSWORD_LEN:
        return render_login_error("Invalid credentials", 401)

    otp = (request.form.get("otp") or "").strip()
    otp_method = (request.form.get("otp_method") or "").strip()

    s = get_session()
    row = None
    try:
        row = (
            s.query(DbUser)
            .filter(DbUser.username == username)
            .order_by(DbUser.id.desc())
            .first()
        )
    finally:
        s.close()

    error_msg = "Invalid credentials"
    if not row:
        _equalize_auth_timing(password)
        audit(
            "login.failure",
            outcome="failure",
            actor_username=username or None,
            detail={"reason": "unknown_user"},
        )
        return render_login_error(error_msg, 401)

    user_id = row.id
    username = row.username
    password_hash = row.password_hash
    totp_secret = row.totp_secret
    totp_enabled = bool(row.totp_enabled)
    failed_attempts = int(row.failed_attempts or 0)
    locked_until = row.locked_until
    email_otp_enabled = bool(row.email_otp_enabled)
    email_otp_code = row.email_otp_code
    email_otp_code_expires = row.email_otp_code_expires

    if locked_until:
        if utcnow() < datetime.fromisoformat(locked_until):
            audit(
                "login.failure",
                outcome="failure",
                actor_id=user_id,
                actor_username=username,
                detail={"reason": "account_locked"},
            )
            return render_login_error("Account locked. Try later.", 403)

    try:
        ph.verify(password_hash, password)
        if ph.check_needs_rehash(password_hash):
            new_hash = ph.hash(password)
            s = get_session()
            try:
                u = s.get(DbUser, int(user_id))
                if u:
                    u.password_hash = new_hash
                    s.commit()
            finally:
                s.close()

    except VerifyMismatchError:
        failed_attempts += 1

        audit(
            "login.failure",
            outcome="failure",
            actor_id=user_id,
            actor_username=username,
            detail={"reason": "bad_password", "attempts": failed_attempts},
        )

        if failed_attempts >= 5:
            lock_time = utcnow() + timedelta(minutes=15)
            s = get_session()
            try:
                u = s.get(DbUser, int(user_id))
                if u:
                    u.failed_attempts = failed_attempts
                    u.locked_until = lock_time.isoformat()
                    s.commit()
            finally:
                s.close()
        else:
            s = get_session()
            try:
                u = s.get(DbUser, int(user_id))
                if u:
                    u.failed_attempts = failed_attempts
                    s.commit()
            finally:
                s.close()
        return render_login_error(error_msg, 401)

    def _otp_fail():
        _record_password_failure(user_id)
        audit(
            "login.failure",
            outcome="failure",
            actor_id=user_id,
            actor_username=username,
            detail={"reason": "bad_otp"},
        )
        return render_login_error(error_msg, 401)

    try:
        if not totp_enabled and not email_otp_enabled:
            pass

        elif totp_enabled and not email_otp_enabled:
            if not otp or not totp_secret:
                return _otp_fail()
            totp = pyotp.TOTP(totp_secret)
            if not totp.verify(otp, valid_window=1):
                return _otp_fail()

        elif email_otp_enabled and not totp_enabled:
            if not otp or not email_otp_code or not email_otp_code_expires:
                return _otp_fail()
            try:
                expires_at = datetime.fromisoformat(email_otp_code_expires)
            except Exception:
                return _otp_fail()
            if utcnow() > expires_at or not _otp_matches(otp, email_otp_code):
                return _otp_fail()
            s = get_session()
            try:
                u = s.get(DbUser, int(user_id))
                if u:
                    u.email_otp_code = None
                    u.email_otp_code_expires = None
                    s.commit()
            finally:
                s.close()

        else:
            if otp_method == "totp":
                if not otp or not totp_secret:
                    return _otp_fail()
                totp = pyotp.TOTP(totp_secret)
                if not totp.verify(otp, valid_window=1):
                    return _otp_fail()

            elif otp_method == "email":
                if not otp or not email_otp_code or not email_otp_code_expires:
                    return _otp_fail()
                try:
                    expires_at = datetime.fromisoformat(email_otp_code_expires)
                except Exception:
                    return _otp_fail()
                if utcnow() > expires_at or not _otp_matches(otp, email_otp_code):
                    return _otp_fail()
                s = get_session()
                try:
                    u = s.get(DbUser, int(user_id))
                    if u:
                        u.email_otp_code = None
                        u.email_otp_code_expires = None
                        s.commit()
                finally:
                    s.close()
            else:
                return _otp_fail()
    except Exception:
        return render_login_error(error_msg, 401)

    s = get_session()
    try:
        u = s.get(DbUser, int(user_id))
        if u:
            u.failed_attempts = 0
            u.locked_until = None
            s.commit()
            # Build the in-memory user object using the canonical DB role
            session.clear()
            session.permanent = True
            session["pwd_fp"] = _pwd_fingerprint(u.password_hash)
            login_user(
                User(
                    id=u.id,
                    username=u.username,
                    password_hash=u.password_hash,
                    role=u.role,
                    totp_secret=u.totp_secret,
                    totp_enabled=u.totp_enabled,
                )
            )
            audit(
                "login.success",
                actor_id=u.id,
                actor_username=u.username,
                detail={
                    "totp_enabled": bool(u.totp_enabled),
                    "email_otp_enabled": bool(u.email_otp_enabled),
                },
            )
    finally:
        s.close()

    return redirect("/dashboard")


@app.route("/check_totp", methods=["POST"])
@limiter.limit("5 per minute")
@csrf_protect
def check_totp():
    data = request.json or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    if not username or not password:
        return api_error("Missing fields", status_code=400)

    if len(username) > MAX_USERNAME_LEN or len(password) > MAX_PASSWORD_LEN:
        return api_error("Invalid credentials", status_code=401)

    s = get_session()
    try:
        user = (
            s.query(DbUser)
            .filter(DbUser.username == username)
            .order_by(DbUser.id.desc())
            .first()
        )
        if not user:
            _equalize_auth_timing(password)
            audit(
                "login.failure",
                outcome="failure",
                actor_username=username or None,
                detail={"reason": "unknown_user", "stage": "check_totp"},
            )
            return api_error("Invalid credentials", status_code=401)

        if _check_account_locked(user):
            audit(
                "login.failure",
                outcome="failure",
                actor_id=user.id,
                actor_username=user.username,
                detail={"reason": "account_locked", "stage": "check_totp"},
            )
            return api_error("Account locked. Try later.", status_code=403)

        try:
            ph.verify(user.password_hash, password)
        except VerifyMismatchError:
            _record_password_failure(user.id)
            audit(
                "login.failure",
                outcome="failure",
                actor_id=user.id,
                actor_username=user.username,
                detail={"reason": "bad_password", "stage": "check_totp"},
            )
            return api_error("Invalid credentials", status_code=401)

        # Do NOT reset failed_attempts here: reset happens only after full
        # MFA success in /login. Resetting now would let a valid password
        # clear the lockout counter before the second factor is verified.

        totp_enabled = bool(user.totp_enabled)
        email_otp_enabled = bool(user.email_otp_enabled)
        masked = (
            mask_email(user.email)
            if getattr(user, "email", None) and email_otp_enabled
            else ""
        )
        return api_ok(
            {
                "totp_required": totp_enabled,
                "totp_enabled": totp_enabled,
                "email_otp_enabled": email_otp_enabled,
                "masked_email": masked,
            }
        )
    finally:
        s.close()


@app.route("/start_login_email_otp", methods=["POST"])
@limiter.limit("5 per minute")
@csrf_protect
def start_login_email_otp():
    """
    Starts email-based OTP for the login flow (before the user is authenticated).
    Expects JSON: {"username": "...", "password": "..."}
    """
    data = request.json or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    if not username or not password:
        return api_error("Missing fields", status_code=400)

    if len(username) > MAX_USERNAME_LEN or len(password) > MAX_PASSWORD_LEN:
        return api_error("Invalid credentials", status_code=401)

    s = get_session()
    try:
        user = (
            s.query(DbUser)
            .filter(DbUser.username == username)
            .order_by(DbUser.id.desc())
            .first()
        )
        if not user:
            _equalize_auth_timing(password)
            audit(
                "login.failure",
                outcome="failure",
                actor_username=username or None,
                detail={"reason": "unknown_user", "stage": "start_login_email_otp"},
            )
            return api_error("Invalid credentials", status_code=401)

        if _check_account_locked(user):
            audit(
                "login.failure",
                outcome="failure",
                actor_id=user.id,
                actor_username=user.username,
                detail={"reason": "account_locked", "stage": "start_login_email_otp"},
            )
            return api_error("Account locked. Try later.", status_code=403)

        try:
            ph.verify(user.password_hash, password)
        except VerifyMismatchError:
            _record_password_failure(user.id)
            audit(
                "login.failure",
                outcome="failure",
                actor_id=user.id,
                actor_username=user.username,
                detail={"reason": "bad_password", "stage": "start_login_email_otp"},
            )
            return api_error("Invalid credentials", status_code=401)

        # Do NOT reset failed_attempts here: reset only after full MFA
        # success in /login.

        if not user.email or not user.email_otp_enabled:
            audit(
                "mfa.email.login_start",
                outcome="failure",
                actor_id=user.id,
                actor_username=user.username,
                detail={"reason": "email_otp_not_enabled"},
            )
            return api_error(
                "Email-based OTP is not enabled for this account.", status_code=400
            )

        code = f"{secrets.randbelow(10**6):06d}"
        expires_at = (utcnow() + timedelta(minutes=5)).isoformat()

        user.email_otp_code = code
        user.email_otp_code_expires = expires_at
        s.commit()

        try:
            send_email_otp(user.email, code, purpose="Login verification")
        except Exception:
            audit(
                "mfa.email.login_start",
                outcome="failure",
                actor_id=user.id,
                actor_username=user.username,
                detail={"reason": "smtp_send_failed"},
            )
            return api_error("Failed to send email code.", status_code=500)

        audit(
            "mfa.email.login_start",
            actor_id=user.id,
            actor_username=user.username,
            detail={"reason": "code_sent"},
        )
        return api_ok({"ok": True})
    finally:
        s.close()


@app.route("/settings")
@login_required
def settings():
    s = get_session()
    try:
        user = s.get(DbUser, int(current_user.id))
    finally:
        s.close()

    username = user.username if user else current_user.username
    email = user.email if user else None
    totp_enabled = bool(user.totp_enabled) if user else False
    email_otp_enabled = bool(user.email_otp_enabled) if user else False
    avatar_path = user.avatar_path if user else None

    avatar_url = None
    if avatar_path:
        avatar_url = "/user_avatar"

    error = session.pop("settings_error", None)
    show_totp_qr = session.pop("show_totp_qr", False)
    return render_template(
        "settings.html",
        username=username,
        email=email,
        totp_enabled=totp_enabled,
        email_otp_enabled=email_otp_enabled,
        masked_email=mask_email(email) if email else "",
        error=error,
        show_totp_qr=show_totp_qr,
        avatar_url=avatar_url,
    )


@app.route("/user_avatar")
@login_required
def user_avatar():
    s = get_session()
    try:
        user = s.get(DbUser, int(current_user.id))
    finally:
        s.close()

    if not user or not user.avatar_path:
        abort(404)

    avatar_path = user.avatar_path
    full_path = os.path.join(os.path.dirname(__file__), avatar_path)

    if not os.path.isfile(full_path):
        abort(404)

    return send_file(full_path)


@app.route("/enable_totp", methods=["POST"])
@login_required
@csrf_protect
def enable_totp():
    s = get_session()
    try:
        user = s.get(DbUser, int(current_user.id))
        if not user:
            audit("mfa.totp.enable", outcome="failure", detail={"reason": "user_not_found"})
            return "User not found", 404
        if user.totp_enabled:
            audit(
                "mfa.totp.enable",
                outcome="failure",
                actor_id=user.id,
                actor_username=user.username,
                detail={"reason": "already_enabled"},
            )
            return "TOTP already enabled", 400

        # Stash candidate secret in session. Only commit after verification.
        session["totp_setup_secret"] = pyotp.random_base32()
        session["totp_setup_qr_shown"] = False
        session["show_totp_qr"] = True
        audit(
            "mfa.totp.setup_started",
            actor_id=user.id,
            actor_username=user.username,
        )
    finally:
        s.close()

    return redirect("/settings")


@app.route("/disable_totp", methods=["POST"])
@login_required
@limiter.limit("10 per hour")
@csrf_protect
def disable_totp():
    if request.is_json:
        data = request.json or {}
        password = data.get("confirm_password")
        otp = data.get("otp")
    else:
        password = request.form.get("confirm_password")
        otp = request.form.get("otp")

    if not password or not otp:
        audit("mfa.totp.disable", outcome="failure", detail={"reason": "missing_fields"})
        if request.is_json:
            return jsonify({"ok": False, "error": "Missing fields"}), 400
        session["settings_error"] = "Missing fields"
        return redirect("/settings")

    if len(password) > MAX_PASSWORD_LEN:
        audit("mfa.totp.disable", outcome="failure", detail={"reason": "password_too_long"})
        if request.is_json:
            return jsonify({"ok": False, "error": "Invalid password"}), 400
        session["settings_error"] = "Invalid password"
        return redirect("/settings")

    s = get_session()
    try:
        user = s.get(DbUser, int(current_user.id))

        if not user:
            audit("mfa.totp.disable", outcome="failure", detail={"reason": "user_not_found"})
            if request.is_json:
                return jsonify({"ok": False, "error": "User not found"}), 404
            session["settings_error"] = "User not found"
            return redirect("/settings")

        if not user.totp_enabled:
            audit(
                "mfa.totp.disable",
                outcome="failure",
                actor_id=user.id,
                actor_username=user.username,
                detail={"reason": "not_enabled"},
            )
            if request.is_json:
                return jsonify({"ok": False, "error": "TOTP not enabled"}), 400
            session["settings_error"] = "TOTP not enabled"
            return redirect("/settings")

        try:
            ph.verify(user.password_hash, password)
        except VerifyMismatchError:
            audit(
                "mfa.totp.disable",
                outcome="failure",
                actor_id=user.id,
                actor_username=user.username,
                detail={"reason": "bad_password"},
            )
            if request.is_json:
                return jsonify({"ok": False, "error": "Invalid password"}), 400
            session["settings_error"] = "Invalid password"
            return redirect("/settings")

        totp = pyotp.TOTP(user.totp_secret)
        if not totp.verify(otp, valid_window=1):
            audit(
                "mfa.totp.disable",
                outcome="failure",
                actor_id=user.id,
                actor_username=user.username,
                detail={"reason": "bad_otp"},
            )
            if request.is_json:
                return jsonify({"ok": False, "error": "Invalid OTP"}), 400
            session["settings_error"] = "Invalid OTP"
            return redirect("/settings")

        user.totp_enabled = False
        user.totp_secret = None
        user.totp_qr_shown = False
        s.commit()
        audit("mfa.totp.disable", actor_id=user.id, actor_username=user.username)
    finally:
        s.close()

    session.pop("totp_setup_secret", None)
    session.pop("totp_setup_qr_shown", None)

    if request.is_json:
        return jsonify({"ok": True}), 200
    return redirect("/settings")


@app.route("/verify_new_totp", methods=["POST"])
@login_required
@limiter.limit("10 per hour")
@csrf_protect
def verify_new_totp():
    data = request.json or {}
    otp = (data.get("otp") or "").strip()

    if not otp:
        audit("mfa.totp.enable", outcome="failure", detail={"reason": "missing_otp"})
        return jsonify({"ok": False, "error": "Missing OTP"}), 400

    pending_secret = session.get("totp_setup_secret")
    if not pending_secret:
        audit("mfa.totp.enable", outcome="failure", detail={"reason": "no_pending_setup"})
        return jsonify({"ok": False, "error": "No pending TOTP setup"}), 400

    totp = pyotp.TOTP(pending_secret)
    if not totp.verify(otp, valid_window=1):
        # Do NOT disable or clear anything — allow retry while pending.
        audit("mfa.totp.enable", outcome="failure", detail={"reason": "bad_otp"})
        return jsonify({"ok": False, "error": "Invalid OTP"}), 400

    s = get_session()
    try:
        user = s.get(DbUser, int(current_user.id))
        if not user:
            audit("mfa.totp.enable", outcome="failure", detail={"reason": "user_not_found"})
            return jsonify({"ok": False, "error": "User not found"}), 404

        user.totp_secret = pending_secret
        user.totp_enabled = True
        user.totp_qr_shown = True
        s.commit()
        audit("mfa.totp.enable", actor_id=user.id, actor_username=user.username)
    finally:
        s.close()

    session.pop("totp_setup_secret", None)
    session.pop("totp_setup_qr_shown", None)
    return jsonify({"ok": True}), 200


@app.route("/change_password", methods=["POST"])
@login_required
@limiter.limit("5 per hour")
@csrf_protect
def change_password():

    current_password = request.form.get("current_password")
    new_password = request.form.get("new_password")
    otp = (request.form.get("otp") or "").strip()

    if not current_password or not new_password:
        audit("password.change", outcome="failure", detail={"reason": "missing_fields"})
        session["settings_error"] = "Missing password fields"
        return redirect("/settings")

    if len(current_password) > MAX_PASSWORD_LEN:
        audit("password.change", outcome="failure", detail={"reason": "current_password_too_long"})
        session["settings_error"] = "Current password is incorrect"
        return redirect("/settings")

    if len(new_password) < 12:
        audit("password.change", outcome="failure", detail={"reason": "new_password_too_short"})
        session["settings_error"] = "Password must be at least 12 characters"
        return redirect("/settings")

    if len(new_password) > MAX_PASSWORD_LEN:
        audit("password.change", outcome="failure", detail={"reason": "new_password_too_long"})
        session["settings_error"] = f"Password cant be more than {MAX_PASSWORD_LEN} characters"
        return redirect("/settings")

    if current_password == new_password:
        audit("password.change", outcome="failure", detail={"reason": "same_password"})
        session["settings_error"] = "Passwords should be different"
        return redirect("/settings")

    s = get_session()
    try:
        user = s.get(DbUser, int(current_user.id))
        if not user:
            audit("password.change", outcome="failure", detail={"reason": "user_not_found"})
            session["settings_error"] = "User not found"
            return redirect("/settings")

        # If TOTP is enabled, require a valid OTP before changing password.
        if user.totp_enabled:
            if not otp or not user.totp_secret:
                audit(
                    "password.change",
                    outcome="failure",
                    actor_id=user.id,
                    actor_username=user.username,
                    detail={"reason": "otp_required"},
                )
                session["settings_error"] = "OTP required"
                return redirect("/settings")
            if not pyotp.TOTP(user.totp_secret).verify(otp, valid_window=1):
                audit(
                    "password.change",
                    outcome="failure",
                    actor_id=user.id,
                    actor_username=user.username,
                    detail={"reason": "bad_otp"},
                )
                session["settings_error"] = "Invalid OTP"
                return redirect("/settings")

        try:
            ph.verify(user.password_hash, current_password)
        except VerifyMismatchError:
            audit(
                "password.change",
                outcome="failure",
                actor_id=user.id,
                actor_username=user.username,
                detail={"reason": "bad_current_password"},
            )
            session["settings_error"] = "Current password is incorrect"
            return redirect("/settings")

        user.password_hash = ph.hash(new_password)
        s.commit()
        audit("password.change", actor_id=user.id, actor_username=user.username)
    finally:
        s.close()

    # Force re-login so the new pwd_fp is required.
    logout_user()
    session.clear()
    return redirect("/login")


@app.route("/update_profile", methods=["POST"])
@login_required
@limiter.limit("30 per hour")
@csrf_protect
def update_profile():
    username = (request.form.get("username") or "").strip()
    email = (request.form.get("email") or "").strip() or None
    avatar = request.files.get("avatar")
    confirm_password = request.form.get("confirm_password") or ""

    if not username:
        audit("profile.update", outcome="failure", detail={"reason": "missing_username"})
        session["settings_error"] = "Username is required"
        return redirect("/settings")

    if not USERNAME_RE.fullmatch(username):
        audit("profile.update", outcome="failure",
              detail={"reason": "invalid_username", "username": username})
        session["settings_error"] = (
            "Username must be 3-30 characters (letters, numbers, _ and - only)"
        )
        return redirect("/settings")

    if email and not EMAIL_RE.fullmatch(email):
        audit("profile.update", outcome="failure",
              detail={"reason": "invalid_email", "email": email})
        session["settings_error"] = "Invalid email address"
        return redirect("/settings")

    s = get_session()
    try:
        existing = (
            s.query(DbUser)
            .filter(DbUser.username == username, DbUser.id != int(current_user.id))
            .first()
        )
        if existing:
            audit("profile.update", outcome="failure",
                  detail={"reason": "duplicate_username", "username": username})
            session["settings_error"] = "Username already taken"
            return redirect("/settings")

        user = s.get(DbUser, int(current_user.id))
        if not user:
            audit("profile.update", outcome="failure", detail={"reason": "user_not_found"})
            session["settings_error"] = "User not found"
            return redirect("/settings")

        # Require password re-auth for profile changes.
        if not confirm_password or len(confirm_password) > MAX_PASSWORD_LEN:
            audit(
                "profile.update",
                outcome="failure",
                actor_id=user.id,
                actor_username=user.username,
                detail={"reason": "missing_password_confirmation"},
            )
            session["settings_error"] = "Password confirmation required"
            return redirect("/settings")
        try:
            ph.verify(user.password_hash, confirm_password)
        except VerifyMismatchError:
            audit(
                "profile.update",
                outcome="failure",
                actor_id=user.id,
                actor_username=user.username,
                detail={"reason": "bad_password"},
            )
            session["settings_error"] = "Invalid password"
            return redirect("/settings")

        old_username = user.username
        old_avatar_path = user.avatar_path

        avatar_path = old_avatar_path
        # Avatar is optional on this endpoint: only touch file handling when
        # one was actually uploaded.
        if avatar and avatar.filename:
            allowed_mimes = {"image/png", "image/jpeg"}
            if avatar.mimetype not in allowed_mimes:
                audit(
                    "profile.update",
                    outcome="failure",
                    actor_id=user.id,
                    actor_username=user.username,
                    detail={"reason": "avatar_bad_mimetype", "mimetype": avatar.mimetype},
                )
                session["settings_error"] = "Invalid image type for avatar"
                return redirect("/settings")

            filename = secure_filename(avatar.filename)
            ext = os.path.splitext(filename)[1].lower()
            allowed_exts = {".png", ".jpg", ".jpeg"}
            if not ext or ext not in allowed_exts:
                audit(
                    "profile.update",
                    outcome="failure",
                    actor_id=user.id,
                    actor_username=user.username,
                    detail={"reason": "avatar_bad_extension", "ext": ext},
                )
                session["settings_error"] = "Invalid image file extension for avatar"
                return redirect("/settings")

            avatar.stream.seek(0, os.SEEK_END)
            size = avatar.stream.tell()
            avatar.stream.seek(0)
            if size > 2 * 1024 * 1024:
                audit(
                    "profile.update",
                    outcome="failure",
                    actor_id=user.id,
                    actor_username=user.username,
                    detail={"reason": "avatar_too_large", "size": size},
                )
                session["settings_error"] = "Avatar image too large (max 2MB)"
                return redirect("/settings")

            avatar.stream.seek(0)
            try:
                probe = Image.open(avatar.stream)
                probe.verify()
                detected = (probe.format or "").upper()
            except Exception:
                audit(
                    "profile.update",
                    outcome="failure",
                    actor_id=user.id,
                    actor_username=user.username,
                    detail={"reason": "avatar_invalid_content"},
                )
                session["settings_error"] = "Invalid image content"
                return redirect("/settings")
            finally:
                avatar.stream.seek(0)

            if detected not in {"JPEG", "PNG"}:
                audit(
                    "profile.update",
                    outcome="failure",
                    actor_id=user.id,
                    actor_username=user.username,
                    detail={"reason": "avatar_unsupported_format", "format": detected},
                )
                session["settings_error"] = "Invalid image content"
                return redirect("/settings")

            avatar.stream.seek(0)
            raw_bytes = avatar.stream.read()
            avatar.stream.seek(0)
            if not _clamav_scan_clean(raw_bytes):
                audit(
                    "profile.update",
                    outcome="failure",
                    actor_id=user.id,
                    actor_username=user.username,
                    detail={"reason": "avatar_malware_detected"},
                )
                session["settings_error"] = "Uploaded file failed the malware scan"
                return redirect("/settings")

            Image.MAX_IMAGE_PIXELS = 10_000_000
            try:
                avatar.stream.seek(0)
                img = Image.open(avatar.stream)

                if img.width > 2000 or img.height > 2000:
                    audit(
                        "profile.update",
                        outcome="failure",
                        actor_id=user.id,
                        actor_username=user.username,
                        detail={
                            "reason": "avatar_dimensions_too_large",
                            "width": img.width,
                            "height": img.height,
                        },
                    )
                    session["settings_error"] = "Image dimensions too large, maximum is 2000x2000"
                    return redirect("/settings")
            except Exception:
                audit(
                    "profile.update",
                    outcome="failure",
                    actor_id=user.id,
                    actor_username=user.username,
                    detail={"reason": "avatar_decode_failed"},
                )
                session["settings_error"] = "Uploaded file is not a valid image"
                return redirect("/settings")
            finally:
                avatar.stream.seek(0)

            upload_dir = os.path.join(os.path.dirname(__file__), "uploads", "avatars")
            os.makedirs(upload_dir, exist_ok=True)
            # Filename is derived only from the numeric user id and a random
            # token -- never from attacker-controlled input like `username`.
            random_name = f"user_{current_user.id}_{secrets.token_hex(32)}.jpg"
            avatar_path = os.path.join("uploads", "avatars", random_name)
            full_path = os.path.join(os.path.dirname(__file__), avatar_path)
            img = img.convert("RGB")
            img.save(full_path, format="JPEG", quality=85)

            if old_avatar_path:
                old_full = os.path.join(os.path.dirname(__file__), old_avatar_path)
                try:
                    if os.path.isfile(old_full):
                        os.remove(old_full)
                except Exception:
                    pass

        user.username = username
        user.email = email
        user.avatar_path = avatar_path
        s.commit()
        audit(
            "profile.update",
            actor_id=user.id,
            actor_username=old_username,
            detail={
                "username_changed": username != old_username,
                "email_changed": email != old_username,
                "avatar_changed": avatar_path != old_avatar_path,
            },
        )
    finally:
        s.close()

    if username != old_username:
        logout_user()
        return redirect("/login")

    return redirect("/settings")


@app.route("/logout")
@login_required
def logout():
    audit("logout")
    logout_user()
    session.clear()
    return redirect("/login")


@app.route("/totp_qr")
@login_required
def totp_qr():
    secret = session.get("totp_setup_secret")
    qr_shown_key = "totp_setup_qr_shown"

    if not secret:
        s = get_session()
        try:
            user = s.get(DbUser, int(current_user.id))
            if not user or not user.totp_secret:
                audit("mfa.totp.qr", outcome="failure", detail={"reason": "totp_not_enabled"})
                return "TOTP not enabled", 400
            if user.totp_qr_shown:
                audit(
                    "mfa.totp.qr",
                    outcome="failure",
                    actor_id=user.id,
                    actor_username=user.username,
                    detail={"reason": "already_shown"},
                )
                return "TOTP QR code can be shown only once", 400
            secret = user.totp_secret
            user.totp_qr_shown = True
            s.commit()
        finally:
            s.close()
    else:
        if session.get(qr_shown_key):
            audit("mfa.totp.qr", outcome="failure", detail={"reason": "already_shown"})
            return "TOTP QR code can be shown only once", 400
        session[qr_shown_key] = True

    uri = pyotp.TOTP(secret).provisioning_uri(
        name=current_user.username,
        issuer_name="Enterprise-AI-Based-IDS",
    )

    img = qrcode.make(uri, box_size=4, border=2)
    buf = io.BytesIO()
    img.save(buf)
    buf.seek(0)
    audit("mfa.totp.qr", detail={"reason": "shown"})
    return send_file(buf, mimetype="image/png")


@app.route("/start_email_otp", methods=["POST"])
@login_required
@limiter.limit("5 per minute")
@csrf_protect
def start_email_otp():
    s = get_session()
    try:
        user = s.get(DbUser, int(current_user.id))
        if not user or not user.email:
            audit("mfa.email.enable", outcome="failure", detail={"reason": "email_not_set"})
            return jsonify({"ok": False, "error": "Email not set for your account."}), 400

        email = user.email

        code = f"{secrets.randbelow(10**6):06d}"
        expires_at = (utcnow() + timedelta(minutes=5)).isoformat()

        user.email_otp_code = code
        user.email_otp_code_expires = expires_at
        s.commit()
    finally:
        s.close()

    try:
        send_email_otp(email, code, purpose="Email-based OTP setup")
    except Exception:
        audit("mfa.email.enable", outcome="failure", detail={"reason": "smtp_send_failed"})
        return jsonify({"ok": False, "error": "Failed to send email."}), 500

    return jsonify({"ok": True}), 200


@app.route("/start_email_otp_disable", methods=["POST"])
@login_required
@limiter.limit("5 per minute")
@csrf_protect
def start_email_otp_disable():
    """
    Starts the disable flow for email-based OTP by sending a new code.
    The user must later confirm this code via /disable_email_otp.
    """
    s = get_session()
    try:
        user = s.get(DbUser, int(current_user.id))
        if not user or not user.email:
            audit("mfa.email.disable", outcome="failure", detail={"reason": "email_not_set"})
            return jsonify({"ok": False, "error": "Email not set for your account."}), 400

        email = user.email
        email_otp_enabled = bool(user.email_otp_enabled)

        if not email_otp_enabled:
            audit(
                "mfa.email.disable",
                outcome="failure",
                actor_id=user.id,
                actor_username=user.username,
                detail={"reason": "not_enabled"},
            )
            return jsonify({"ok": False, "error": "Email-based OTP is not enabled."}), 400

        code = f"{secrets.randbelow(10**6):06d}"
        expires_at = (utcnow() + timedelta(minutes=5)).isoformat()

        user.email_otp_code = code
        user.email_otp_code_expires = expires_at
        s.commit()
    finally:
        s.close()

    try:
        send_email_otp(email, code, purpose="Disable email-based OTP")
    except Exception:
        audit("mfa.email.disable", outcome="failure", detail={"reason": "smtp_send_failed"})
        return jsonify({"ok": False, "error": "Failed to send email."}), 500

    return jsonify({"ok": True}), 200


@app.route("/verify_email_otp", methods=["POST"])
@login_required
@limiter.limit("5 per minute")
@csrf_protect
def verify_email_otp():
    data = request.json or {}
    otp = (data.get("otp") or "").strip()

    if not otp:
        audit("mfa.email.enable", outcome="failure", detail={"reason": "missing_code"})
        return jsonify({"ok": False, "error": "Missing code."}), 400

    s = get_session()
    try:
        user = s.get(DbUser, int(current_user.id))
        if not user:
            audit("mfa.email.enable", outcome="failure", detail={"reason": "user_not_found"})
            return jsonify({"ok": False, "error": "User not found."}), 404

        stored_code = user.email_otp_code
        expires_str = user.email_otp_code_expires

        if not stored_code or not expires_str:
            audit(
                "mfa.email.enable",
                outcome="failure",
                actor_id=user.id,
                actor_username=user.username,
                detail={"reason": "no_pending_code"},
            )
            return jsonify({"ok": False, "error": "No pending email OTP setup."}), 400

        try:
            expires_at = datetime.fromisoformat(expires_str)
        except Exception:
            audit(
                "mfa.email.enable",
                outcome="failure",
                actor_id=user.id,
                actor_username=user.username,
                detail={"reason": "invalid_code_state"},
            )
            return jsonify({"ok": False, "error": "Invalid code state."}), 400

        if utcnow() > expires_at:
            audit(
                "mfa.email.enable",
                outcome="failure",
                actor_id=user.id,
                actor_username=user.username,
                detail={"reason": "code_expired"},
            )
            return jsonify({"ok": False, "error": "Code expired."}), 400

        if not _otp_matches(otp, stored_code):
            audit(
                "mfa.email.enable",
                outcome="failure",
                actor_id=user.id,
                actor_username=user.username,
                detail={"reason": "bad_code"},
            )
            return jsonify({"ok": False, "error": "Invalid code."}), 400

        user.email_otp_enabled = True
        user.email_otp_code = None
        user.email_otp_code_expires = None
        s.commit()
        audit("mfa.email.enable", actor_id=user.id, actor_username=user.username)
        return jsonify({"ok": True}), 200
    finally:
        s.close()


@app.route("/disable_email_otp", methods=["POST"])
@login_required
@limiter.limit("5 per minute")
@csrf_protect
def disable_email_otp():
    data = request.json or {}
    password = (data.get("confirm_password") or "").strip()
    otp = (data.get("otp") or "").strip()

    if not password or not otp:
        audit("mfa.email.disable", outcome="failure", detail={"reason": "missing_fields"})
        return jsonify({"ok": False, "error": "Missing fields."}), 400

    if len(password) > MAX_PASSWORD_LEN:
        audit("mfa.email.disable", outcome="failure", detail={"reason": "password_too_long"})
        return jsonify({"ok": False, "error": "Invalid password."}), 400

    s = get_session()
    try:
        user = s.get(DbUser, int(current_user.id))
        if not user:
            audit("mfa.email.disable", outcome="failure", detail={"reason": "user_not_found"})
            return jsonify({"ok": False, "error": "User not found."}), 404

        password_hash = user.password_hash
        email_otp_enabled = bool(user.email_otp_enabled)
        stored_code = user.email_otp_code
        expires_str = user.email_otp_code_expires

        if not email_otp_enabled:
            audit(
                "mfa.email.disable",
                outcome="failure",
                actor_id=user.id,
                actor_username=user.username,
                detail={"reason": "not_enabled"},
            )
            return jsonify({"ok": False, "error": "Email-based OTP is not enabled."}), 400

        try:
            ph.verify(password_hash, password)
        except VerifyMismatchError:
            audit(
                "mfa.email.disable",
                outcome="failure",
                actor_id=user.id,
                actor_username=user.username,
                detail={"reason": "bad_password"},
            )
            return jsonify({"ok": False, "error": "Invalid password."}), 400

        if not stored_code or not expires_str:
            audit(
                "mfa.email.disable",
                outcome="failure",
                actor_id=user.id,
                actor_username=user.username,
                detail={"reason": "no_pending_code"},
            )
            return jsonify({"ok": False, "error": "No verification code found. Start disable flow again."}), 400

        try:
            expires_at = datetime.fromisoformat(expires_str)
        except Exception:
            audit(
                "mfa.email.disable",
                outcome="failure",
                actor_id=user.id,
                actor_username=user.username,
                detail={"reason": "invalid_code_state"},
            )
            return jsonify({"ok": False, "error": "Invalid code state."}), 400

        if utcnow() > expires_at:
            audit(
                "mfa.email.disable",
                outcome="failure",
                actor_id=user.id,
                actor_username=user.username,
                detail={"reason": "code_expired"},
            )
            return jsonify({"ok": False, "error": "Code expired."}), 400

        if not _otp_matches(otp, stored_code):
            audit(
                "mfa.email.disable",
                outcome="failure",
                actor_id=user.id,
                actor_username=user.username,
                detail={"reason": "bad_code"},
            )
            return jsonify({"ok": False, "error": "Invalid code."}), 400

        user.email_otp_enabled = False
        user.email_otp_code = None
        user.email_otp_code_expires = None
        s.commit()
        audit("mfa.email.disable", actor_id=user.id, actor_username=user.username)
        return jsonify({"ok": True}), 200
    finally:
        s.close()


@app.route("/dashboard")
@login_required
@csrf_protect
@role_required("admin", "soc")
def dashboard():
    return render_template("dashboard.html")

@app.route("/analytics")
@login_required
@role_required("admin", "soc")
def analytics_page():
    return render_template("analytics.html")

@app.route("/audit")
@login_required
@role_required("admin")
def audit_page():
    return render_template("audit.html")


@app.route("/audit/api/entries")
@login_required
@role_required("admin")
def audit_api_entries():
    try:
        rows = query_audit(
            action=(request.args.get("action") or "").strip() or None,
            actor_username=(request.args.get("actor") or "").strip() or None,
            target_type=(request.args.get("target_type") or "").strip() or None,
            outcome=(request.args.get("outcome") or "").strip() or None,
            start_time=request.args.get("start_time", type=float),
            end_time=request.args.get("end_time", type=float),
            before_ts=request.args.get("before_ts", type=float),
            before_id=request.args.get("before_id", type=int),
            limit=request.args.get("limit", default=100, type=int) or 100,
        )
        next_cursor = None
        if rows:
            last = rows[-1]
            next_cursor = {"before_ts": last["ts"], "before_id": last["id"]}
        return api_ok(rows, meta={"next_cursor": next_cursor})
    except Exception as e:
        return api_error(str(e), status_code=500, code="internal_error")


@app.route("/audit/api/actions")
@login_required
@role_required("admin")
def audit_api_actions():
    try:
        return api_ok(audit_actions())
    except Exception as e:
        return api_error(str(e), status_code=500, code="internal_error")


@app.route("/audit/api/stats")
@login_required
@role_required("admin")
def audit_api_stats():
    days = request.args.get("days", default=7, type=int) or 7
    try:
        start_time = time.time() - days * 86400
        return api_ok(audit_stats(start_time=start_time))
    except Exception as e:
        return api_error(str(e), status_code=500, code="internal_error")

@app.route("/admin")
@login_required
@role_required("admin")
def admin_panel():
    return render_template("admin.html")


@app.route("/admin/api/users", methods=["GET"])
@login_required
@role_required("admin")
def admin_list_users():
    page = max(1, request.args.get("page", default=1, type=int) or 1)
    page_size = max(
        1,
        min(request.args.get("page_size", default=25, type=int) or 25, 100),
    )
    q = (request.args.get("q") or "").strip()
    sort = (request.args.get("sort") or "id").lower()
    order = (request.args.get("order") or "desc").lower()

    valid_sorts = {"id", "username", "role", "email", "locked"}
    if sort not in valid_sorts:
        sort = "id"
    if order not in {"asc", "desc"}:
        order = "desc"

    s = get_session()
    try:
        query = s.query(DbUser)

        if q:
            like = f"%{q}%"
            query = query.filter(
                (DbUser.username.ilike(like)) | (DbUser.email.ilike(like))
            )

        if sort == "username":
            sort_col = DbUser.username
        elif sort == "role":
            sort_col = DbUser.role
        elif sort == "email":
            sort_col = DbUser.email
        elif sort == "locked":
            sort_col = DbUser.locked_until
        else:
            sort_col = DbUser.id

        if order == "asc":
            query = query.order_by(sort_col.asc())
        else:
            query = query.order_by(sort_col.desc())

        total = query.count()
        items = (
            query.offset((page - 1) * page_size)
            .limit(page_size)
            .all()
        )

        data = []
        for u in items:
            data.append(
                {
                    "id": u.id,
                    "username": u.username,
                    "role": (u.role or "soc").lower(),
                    "email": u.email,
                    "totp_enabled": bool(u.totp_enabled),
                    "email_otp_enabled": bool(u.email_otp_enabled),
                    "failed_attempts": u.failed_attempts,
                    "locked_until": u.locked_until,
                    "avatar_url": "/admin/user_avatar/{}".format(u.id)
                    if u.avatar_path
                    else None,
                }
            )

        return api_ok(
            data,
            meta={
                "page": page,
                "page_size": page_size,
                "total": total,
            },
        )
    finally:
        s.close()


@app.route("/admin/api/users", methods=["POST"])
@login_required
@role_required("admin")
@csrf_protect
def admin_create_user():
    data = request.json or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    role = (data.get("role") or "soc").strip().lower()
    email = (data.get("email") or "").strip() or None

    if role not in {"admin", "soc"}:
        audit("user.create", outcome="failure",
              detail={"reason": "invalid_role", "role": role, "username": username})
        return jsonify({"ok": False, "error": "Invalid role"}), 400
    if not USERNAME_RE.fullmatch(username or ""):
        audit("user.create", outcome="failure",
              detail={"reason": "invalid_username", "username": username})
        return jsonify({"ok": False, "error": "Invalid username"}), 400
    if len(password) < 12 or len(password) > MAX_PASSWORD_LEN:
        audit("user.create", outcome="failure",
              detail={"reason": "invalid_password_length", "username": username})
        return jsonify({"ok": False, "error": "Password must be 12-64 characters"}), 400

    if email and not EMAIL_RE.fullmatch(email):
        audit("user.create", outcome="failure",
              detail={"reason": "invalid_email", "email": email, "username": username})
        return jsonify({"ok": False, "error": "Invalid email"}), 400

    password_hash = ph.hash(password)
    s = get_session()
    try:
        existing = s.query(DbUser).filter(DbUser.username == username).first()
        if existing:
            audit("user.create", outcome="failure",
                  detail={"reason": "duplicate_username", "username": username})
            return jsonify({"ok": False, "error": "Username already exists"}), 400
        user = DbUser(
            username=username,
            password_hash=password_hash,
            role=role,
            email=email,
        )
        s.add(user)
        s.commit()
        audit(
            "user.create",
            target_type="user",
            target_id=user.id,
            detail={"username": username, "role": role, "email": email},
        )
        return jsonify({"ok": True})
    finally:
        s.close()


@app.route("/admin/api/users/<int:user_id>", methods=["DELETE"])
@login_required
@role_required("admin")
@csrf_protect
def admin_delete_user(user_id: int):
    if int(current_user.id) == int(user_id):
        audit("user.delete", outcome="failure", target_type="user", target_id=user_id,
              detail={"reason": "self_delete_attempt"})
        return jsonify({"ok": False, "error": "You cannot delete your own account."}), 400
    s = get_session()
    try:
        user = s.get(DbUser, int(user_id))
        if not user:
            audit("user.delete", outcome="failure", target_type="user", target_id=user_id,
                  detail={"reason": "not_found"})
            return jsonify({"ok": False, "error": "User not found"}), 404
        target_username = user.username
        s.delete(user)
        s.commit()
        audit(
            "user.delete",
            target_type="user",
            target_id=user_id,
            detail={"username": target_username},
        )
        return jsonify({"ok": True})
    finally:
        s.close()


@app.route("/admin/api/users/<int:user_id>/reset_password", methods=["POST"])
@login_required
@role_required("admin")
@csrf_protect
def admin_reset_password(user_id: int):
    data = request.json or {}
    new_password = data.get("new_password") or ""
    if len(new_password) < 12 or len(new_password) > MAX_PASSWORD_LEN:
        audit("user.reset_password", outcome="failure",
              target_type="user", target_id=user_id,
              detail={"reason": "invalid_password_length"})
        return jsonify({"ok": False, "error": "Password must be 12-64 characters"}), 400

    s = get_session()
    try:
        user = s.get(DbUser, int(user_id))
        if not user:
            audit("user.reset_password", outcome="failure",
                  target_type="user", target_id=user_id,
                  detail={"reason": "not_found"})
            return jsonify({"ok": False, "error": "User not found"}), 404
        user.password_hash = ph.hash(new_password)
        user.failed_attempts = 0
        user.locked_until = None
        s.commit()
        audit(
            "user.reset_password",
            target_type="user",
            target_id=user_id,
            detail={"username": user.username},
        )
        return jsonify({"ok": True})
    finally:
        s.close()


@app.route("/admin/api/users/<int:user_id>/set_role", methods=["POST"])
@login_required
@role_required("admin")
@csrf_protect
def admin_set_role(user_id: int):
    data = request.json or {}
    role = (data.get("role") or "").strip().lower()
    if role not in {"admin", "soc"}:
        audit("user.set_role", outcome="failure",
              target_type="user", target_id=user_id,
              detail={"reason": "invalid_role", "role": role})
        return jsonify({"ok": False, "error": "Invalid role"}), 400
    if int(current_user.id) == int(user_id) and role != "admin":
        audit("user.set_role", outcome="failure",
              target_type="user", target_id=user_id,
              detail={"reason": "self_demote_attempt"})
        return jsonify({"ok": False, "error": "You cannot remove your own admin role."}), 400

    s = get_session()
    try:
        user = s.get(DbUser, int(user_id))
        if not user:
            audit("user.set_role", outcome="failure",
                  target_type="user", target_id=user_id,
                  detail={"reason": "not_found"})
            return jsonify({"ok": False, "error": "User not found"}), 404
        old_role = user.role
        user.role = role
        s.commit()
        audit(
            "user.set_role",
            target_type="user",
            target_id=user_id,
            detail={"username": user.username, "old_role": old_role, "new_role": role},
        )
        return jsonify({"ok": True})
    finally:
        s.close()


@app.route("/admin/api/users/<int:user_id>/reset_mfa", methods=["POST"])
@login_required
@role_required("admin")
@csrf_protect
def admin_reset_mfa(user_id: int):
    """
    Recovery endpoint: clears TOTP secret and email-OTP settings for a user.
    """
    if int(current_user.id) == int(user_id):
        audit("user.reset_mfa", outcome="failure",
              target_type="user", target_id=user_id,
              detail={"reason": "self_target"})
        return jsonify({"ok": False, "error": "Use Settings to manage your own MFA."}), 400

    s = get_session()
    try:
        user = s.get(DbUser, int(user_id))
        if not user:
            audit("user.reset_mfa", outcome="failure",
                  target_type="user", target_id=user_id,
                  detail={"reason": "not_found"})
            return jsonify({"ok": False, "error": "User not found"}), 404

        user.totp_enabled = False
        user.totp_secret = None
        user.totp_qr_shown = False
        user.email_otp_enabled = False
        user.email_otp_code = None
        user.email_otp_code_expires = None
        user.failed_attempts = 0
        user.locked_until = None
        s.commit()
        audit(
            "user.reset_mfa",
            target_type="user",
            target_id=user_id,
            detail={"username": user.username},
        )
        return jsonify({"ok": True})
    finally:
        s.close()


@app.route("/admin/api/users/<int:user_id>/set_lock", methods=["POST"])
@login_required
@role_required("admin")
@csrf_protect
def admin_set_lock(user_id: int):
    data = request.json or {}
    locked = bool(data.get("locked"))

    if int(current_user.id) == int(user_id) and locked:
        audit("user.lock", outcome="failure",
              target_type="user", target_id=user_id,
              detail={"reason": "self_lock_attempt"})
        return jsonify({"ok": False, "error": "You cannot lock your own account."}), 400

    s = get_session()
    try:
        user = s.get(DbUser, int(user_id))
        if not user:
            audit("user.lock", outcome="failure",
                  target_type="user", target_id=user_id,
                  detail={"reason": "not_found"})
            return jsonify({"ok": False, "error": "User not found"}), 404

        if locked:
            lock_time = utcnow() + timedelta(hours=8)
            user.locked_until = lock_time.isoformat()
        else:
            user.locked_until = None
            user.failed_attempts = 0

        s.commit()
        audit(
            "user.lock" if locked else "user.unlock",
            target_type="user",
            target_id=user_id,
            detail={"username": user.username},
        )
        return jsonify({"ok": True})
    finally:
        s.close()


@app.route("/admin/user_avatar/<int:user_id>")
@login_required
@role_required("admin")
def admin_user_avatar(user_id: int):
    s = get_session()
    try:
        user = s.get(DbUser, int(user_id))
        if not user or not user.avatar_path:
            abort(404)
        avatar_path = user.avatar_path
    finally:
        s.close()

    full_path = os.path.join(os.path.dirname(__file__), avatar_path)

    if not os.path.isfile(full_path):
        abort(404)

    return send_file(full_path)

# --- Analytics APIs ---

@app.route("/analytics/api/heatmap")
@login_required
@role_required("admin", "soc")
def analytics_api_heatmap():
    weeks = request.args.get("weeks", default=4, type=int) or 4
    try:
        return api_ok(get_heatmap(weeks=weeks))
    except Exception as e:
        return api_error(str(e), status_code=500, code="internal_error")


@app.route("/analytics/api/recurring-ips")
@login_required
@role_required("admin", "soc")
def analytics_api_recurring_ips():
    min_days = request.args.get("min_days", default=3, type=int) or 3
    lookback_days = request.args.get("days", default=30, type=int) or 30
    try:
        return api_ok(get_recurring_actors(
            field="src_ip", min_days=min_days, lookback_days=lookback_days,
        ))
    except Exception as e:
        return api_error(str(e), status_code=500, code="internal_error")


@app.route("/analytics/api/recurring-hosts")
@login_required
@role_required("admin", "soc")
def analytics_api_recurring_hosts():
    min_days = request.args.get("min_days", default=3, type=int) or 3
    lookback_days = request.args.get("days", default=30, type=int) or 30
    try:
        return api_ok(get_recurring_actors(
            field="host", min_days=min_days, lookback_days=lookback_days,
        ))
    except Exception as e:
        return api_error(str(e), status_code=500, code="internal_error")


@app.route("/analytics/api/top-threats")
@login_required
@role_required("admin", "soc")
def analytics_api_top_threats():
    lookback_days = request.args.get("days", default=30, type=int) or 30
    try:
        return api_ok(get_top_threats(lookback_days=lookback_days))
    except Exception as e:
        return api_error(str(e), status_code=500, code="internal_error")


@app.route("/analytics/api/patterns")
@login_required
@role_required("admin", "soc")
def analytics_api_patterns():
    lookback_days = request.args.get("days", default=60, type=int) or 60
    try:
        ip_patterns = get_periodic_patterns(
            field="src_ip", lookback_days=lookback_days,
        )
        host_patterns = get_periodic_patterns(
            field="host", lookback_days=lookback_days,
        )
        return api_ok({
            "ip_patterns": ip_patterns,
            "host_patterns": host_patterns,
        })
    except Exception as e:
        return api_error(str(e), status_code=500, code="internal_error")


@app.route("/analytics/api/weekly-summary")
@login_required
@role_required("admin", "soc")
def analytics_api_weekly_summary():
    weeks = request.args.get("weeks", default=12, type=int) or 12
    try:
        return api_ok(get_weekly_summary(weeks=weeks))
    except Exception as e:
        return api_error(str(e), status_code=500, code="internal_error")

@app.route("/analytics/api/mitre-coverage")
@login_required
@role_required("admin", "soc")
def analytics_api_mitre_coverage():
    """
    Coverage matrix: for each tactic, which techniques fired in the
    window and how often. Uses the analytics `threat_patterns` table
    for counts, augmented with the static mapping.
    """
    from intelligence.mitre import TACTICS, coverage as mitre_coverage
    from sqlalchemy import func, select
    from storage.db import get_session
    from storage.models import PacketLog

    days = request.args.get("days", default=30, type=int) or 30
    since = time.time() - days * 86400

    session = get_session()
    try:
        # Packet_logs is the source of truth for mitre_json; the aggregation
        # table doesn't split by technique. This is a per-request scan of
        # suspicious/dangerous rows, bounded by the lookback window.
        rows = session.execute(
            select(PacketLog.mitre_json)
            .where(PacketLog.timestamp >= since)
            .where(PacketLog.mitre_json.isnot(None))
            .where(PacketLog.classification.in_(("suspicious", "dangerous")))
        ).all()
    finally:
        session.close()

    counts: dict[str, int] = {}
    for (raw,) in rows:
        try:
            entries = json.loads(raw or "[]")
        except (json.JSONDecodeError, TypeError):
            continue
        if not isinstance(entries, list):
            continue
        for e in entries:
            if isinstance(e, dict) and e.get("technique"):
                counts[e["technique"]] = counts.get(e["technique"], 0) + 1

    mapping = {e["technique"]: e for e in mitre_coverage()}

    by_tactic: dict[str, list[dict]] = {t: [] for t in TACTICS}
    for tech, entry in mapping.items():
        tactic = entry["tactic"]
        by_tactic.setdefault(tactic, []).append({
            "technique": tech,
            "name": entry["name"],
            "count": counts.get(tech, 0),
        })

    for t in by_tactic:
        by_tactic[t].sort(key=lambda e: (-e["count"], e["technique"]))

    total_techniques = len(mapping)
    triggered_techniques = sum(1 for tech in mapping if counts.get(tech, 0) > 0)

    return api_ok({
        "days": days,
        "tactics": TACTICS,
        "by_tactic": by_tactic,
        "total_techniques": total_techniques,
        "triggered_techniques": triggered_techniques,
        "triggered_counts": counts,
    })

# --- SSL decryption management ---

def _ssl_enabled() -> bool:
    return (os.getenv("SSL_DECRYPTION_ENABLED", "false") or "false").lower() == "true"


@app.route("/ssl")
@login_required
@role_required("admin")
def ssl_page():
    return render_template("ssl.html")


@app.route("/ssl/api/status")
@login_required
@role_required("admin")
def ssl_api_status():
    from ssl_inspect import ca as ca_module

    ca_exists = ca_module.ca_exists()
    proc_running = _is_ssl_proc_running()
    return api_ok({
        "enabled": _ssl_enabled(),
        "interceptor_running": proc_running,
        "ca_present": ca_exists,
        "intercept_port": int(os.getenv("SSL_INTERCEPT_PORT", "8443") or "8443"),
    })


@app.route("/ssl/api/ca")
@login_required
@role_required("admin")
def ssl_api_ca_info():
    from storage.db import get_session
    from storage.models import SslConfig

    session = get_session()
    try:
        row = session.get(SslConfig, 1)
    finally:
        session.close()

    if row is None:
        return api_ok(None)

    return api_ok({
        "common_name": row.ca_common_name,
        "serial_hex": row.ca_serial_hex,
        "not_before": row.ca_not_before.isoformat() if row.ca_not_before else None,
        "not_after": row.ca_not_after.isoformat() if row.ca_not_after else None,
        "fingerprint_sha256": row.ca_fingerprint_sha256,
    })


@app.route("/ssl/api/ca/cert.pem")
@login_required
@role_required("admin")
def ssl_api_ca_download():
    from ssl_inspect import ca as ca_module
    if not ca_module.ca_exists():
        abort(404)
    pem = ca_module.read_ca_cert_pem()
    return Response(
        pem,
        mimetype="application/x-pem-file",
        headers={
            "Content-Disposition": 'attachment; filename="enterprise-ai-ids-ca.crt"'
        },
    )


@app.route("/ssl/api/ca/regenerate", methods=["POST"])
@login_required
@role_required("admin")
@csrf_protect
def ssl_api_ca_regenerate():
    """
    Regenerate the root CA. Destructive: every client that trusted the
    old CA must re-install. The interceptor must be restarted for sslsplit
    to pick up the new cert.
    """
    from ssl_inspect import ca as ca_module
    try:
        ca_module.delete_ca()
        cert = ca_module.generate_ca()
        audit(
            "ssl.ca_regenerate",
            target_type="ca",
            detail={"common_name": cert.subject.rfc4514_string()},
        )
        return api_ok({
            "regenerated": True,
            "common_name": cert.subject.rfc4514_string(),
            "message": "Restart the supervisor for the new CA to take effect.",
        })
    except Exception as e:
        audit("ssl.ca_regenerate", outcome="failure", detail={"error": str(e)})
        return api_error(str(e), status_code=500, code="ca_regen_failed")


@app.route("/ssl/api/bypass", methods=["GET"])
@login_required
@role_required("admin")
def ssl_api_bypass_list():
    from sqlalchemy import select
    from storage.db import get_session
    from storage.models import SslBypassRule

    session = get_session()
    try:
        rows = session.execute(
            select(SslBypassRule).order_by(SslBypassRule.id.asc())
        ).scalars().all()
        return api_ok([
            {
                "id": r.id,
                "match_type": r.match_type,
                "pattern": r.pattern,
                "reason": r.reason,
                "enabled": bool(r.enabled),
            }
            for r in rows
        ])
    finally:
        session.close()


@app.route("/ssl/api/bypass", methods=["POST"])
@login_required
@role_required("admin")
@csrf_protect
def ssl_api_bypass_add():
    import re as _re
    from sqlalchemy import select
    from storage.db import get_session
    from storage.models import SslBypassRule

    data = request.json or {}
    match_type = (data.get("match_type") or "").strip().lower()
    pattern = (data.get("pattern") or "").strip()
    reason = (data.get("reason") or "").strip() or None

    if match_type not in ("sni", "ip", "cidr"):
        audit(
            "ssl.bypass.add",
            outcome="failure",
            detail={"reason": "invalid_match_type", "match_type": match_type},
        )
        return api_error("Invalid match_type", status_code=400, code="invalid_match_type")
    if not pattern or len(pattern) > 255:
        audit(
            "ssl.bypass.add",
            outcome="failure",
            detail={"reason": "invalid_pattern", "match_type": match_type},
        )
        return api_error("Invalid pattern", status_code=400, code="invalid_pattern")

    # SNI: allow wildcard patterns like "*.example.com"
    if match_type == "sni":
        if not _re.fullmatch(r"[A-Za-z0-9\.\-\*]+", pattern):
            audit(
                "ssl.bypass.add",
                outcome="failure",
                detail={"reason": "invalid_sni", "pattern": pattern},
            )
            return api_error("SNI pattern may only contain letters, digits, '.', '-', '*'",
                             status_code=400, code="invalid_sni")

    session = get_session()
    try:
        existing = session.execute(
            select(SslBypassRule).where(
                SslBypassRule.match_type == match_type,
                SslBypassRule.pattern == pattern,
            )
        ).scalar_one_or_none()
        if existing:
            audit(
                "ssl.bypass.add",
                outcome="failure",
                detail={"reason": "duplicate", "match_type": match_type, "pattern": pattern},
            )
            return api_error("Rule already exists", status_code=400, code="duplicate")

        rule = SslBypassRule(
            match_type=match_type, pattern=pattern, reason=reason, enabled=True,
        )
        session.add(rule)
        session.commit()
        audit(
            "ssl.bypass.add",
            target_type="bypass_rule",
            target_id=rule.id,
            detail={"match_type": match_type, "pattern": pattern, "reason": reason},
        )
    finally:
        session.close()

    # Best-effort immediate sync; the interceptor's background loop
    # picks up the change within ~30 s if this is not root.
    try:
        from ssl_inspect import bypass as bypass_module
        bypass_module.sync_iptables()
    except Exception:
        import logging
        logging.getLogger(__name__).debug(
            "immediate iptables sync failed; interceptor will catch up",
            exc_info=True,
        )

    return api_ok({"added": True})


@app.route("/ssl/api/bypass/<int:rule_id>", methods=["DELETE"])
@login_required
@role_required("admin")
@csrf_protect
def ssl_api_bypass_delete(rule_id: int):
    from storage.db import get_session
    from storage.models import SslBypassRule
    from ssl_inspect import bypass as bypass_module

    session = get_session()
    try:
        row = session.get(SslBypassRule, rule_id)
        if not row:
            audit(
                "ssl.bypass.delete",
                outcome="failure",
                target_type="bypass_rule",
                target_id=rule_id,
                detail={"reason": "not_found"},
            )
            return api_error("Rule not found", status_code=404, code="not_found")
        detail = {"match_type": row.match_type, "pattern": row.pattern}
        session.delete(row)
        session.commit()
        audit(
            "ssl.bypass.delete",
            target_type="bypass_rule",
            target_id=rule_id,
            detail=detail,
        )
    finally:
        session.close()

    # Best-effort immediate sync. Works only when the web UI runs as root
    # (which it does under main.py). If not root, the interceptor's
    # background sync thread will pick up the change within ~30 seconds.
    try:
        bypass_module.sync_iptables()
    except Exception:
        import logging
        logging.getLogger(__name__).debug(
            "immediate iptables sync failed; interceptor will catch up",
            exc_info=True,
        )

    return api_ok({"deleted": True})


@app.route("/ssl/api/bypass/iptables-status")
@login_required
@role_required("admin")
def ssl_api_bypass_iptables_status():
    """
    Read-only view of the current iptables bypass state. Used by the SSL
    page to indicate whether the DB rules are actually enforced.
    """
    try:
        from ssl_inspect import bypass as bypass_module
        return api_ok(bypass_module.iptables_status())
    except Exception as e:
        return api_error(str(e), status_code=500, code="internal_error")

# --- IDS engine health (dashboard live indicator) ---
@app.route("/ids/health")
@login_required
@role_required("admin", "soc")
def ids_engine_health():
    from intelligence.sensor_process import get_sensor_health

    return api_ok(get_sensor_health())


# --- Sensor telemetry push (ids_engine.py → Web UI stats) ---
_SENSOR_TOKEN_WARNED = False
_sensor_nonce_tracker = NonceTracker()
# De-dupe sensor auth failure audits per (remote_ip, reason). Prevents a
# misconfigured sensor from filling the audit table with thousands of
# identical rows between process restarts.
_SENSOR_AUTH_AUDITED: set[tuple[str, str]] = set()


def _audit_sensor_auth_failure_once(remote_ip: str | None, reason: str) -> None:
    key = (remote_ip or "", reason)
    if key in _SENSOR_AUTH_AUDITED:
        return
    _SENSOR_AUTH_AUDITED.add(key)
    audit(
        "sensor.auth_failure",
        outcome="denied",
        actor_ip=remote_ip,
        detail={"reason": reason, "deduped": True},
    )


@app.route("/ids/update", methods=["POST"])
def ids_sensor_update():
    """
    Receive live counters from the IDS sensor process (api_client.sender).

    Authentication: HMAC-signed request. The sensor sends X-IDS-Timestamp,
    X-IDS-Nonce, and X-IDS-Signature over the canonical representation of
    method / path / timestamp / nonce / SHA256(body). The shared secret is
    never transmitted. See intelligence/sensor_auth.py for the wire format.
    """
    expected_secret = os.environ.get("IDS_SENSOR_TOKEN", "")
    if not expected_secret:
        global _SENSOR_TOKEN_WARNED
        if not _SENSOR_TOKEN_WARNED:
            import logging

            logging.getLogger(__name__).error(
                "IDS_SENSOR_TOKEN is not set; rejecting all /ids/update requests. "
                "Set IDS_SENSOR_TOKEN in the .env shared by uni-srver.py and "
                "ids_engine.py to re-enable sensor telemetry."
            )
            _SENSOR_TOKEN_WARNED = True
        _audit_sensor_auth_failure_once(request.remote_addr, "token_not_configured")
        return api_error(
            "sensor secret not configured",
            status_code=503,
            code="token_not_configured",
        )

    # Raw body bytes are what the signature authenticates — do not read
    # JSON first (that would consume the stream).
    raw_body = request.get_data(cache=True)

    ok, reason = verify_request(
        expected_secret,
        request.method,
        request.path,
        raw_body,
        request.headers,
        _sensor_nonce_tracker,
    )
    if not ok:
        import logging
        logging.getLogger(__name__).warning(
            "Sensor telemetry rejected: %s (remote=%s)",
            reason, request.remote_addr,
        )
        _audit_sensor_auth_failure_once(request.remote_addr, reason)
        return api_error("unauthorized", status_code=401, code=reason)

    body = request.get_json(silent=True) or {}
    incoming = body.get("stats") or {}

    try:
        apply_telemetry_stats(incoming)
    except Exception:
        import logging
        logging.getLogger(__name__).error("Failed to persist telemetry stats", exc_info=True)

    sync_stats_from_persistence()
    payload = load_statistics_for_api()
    broadcast("stats", payload)
    return api_ok({"received": True})


# --- Stats API ---
@app.route("/ids/stats")
@login_required
@role_required("admin", "soc")
def get_stats():
    sync_stats_from_persistence()
    payload = load_statistics_for_api()
    return api_ok(payload)


@app.route("/ids/stream")
@login_required
@role_required("admin", "soc")
def ids_event_stream():
    return Response(sse_stream(), mimetype="text/event-stream")


@app.route("/metrics")
def prometheus_metrics():
    # Restrict scraping to trusted networks.
    if request.remote_addr not in ALLOWED_IPS:
        abort(403)
    return Response(export_prometheus(), mimetype="text/plain; version=0.0.4")


def _safe_json_reasons(raw: str | None) -> list:
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return ["_reasons_json_parse_error"]
    if isinstance(data, list):
        return [str(x) for x in data if x is not None]
    if data is None:
        return []
    return [str(data)]

def _safe_json_mitre(raw: str | None) -> list:
    """Parse mitre_json into a list of {technique, tactic, name} entries."""
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return []
    if not isinstance(data, list):
        return []
    return [x for x in data if isinstance(x, dict) and x.get("technique")]

def _safe_json_object(raw: str | None) -> dict | None:
    """Parse TI / DNS JSON without dropping rows on malformed payloads."""
    if raw is None or raw == "":
        return None
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return {"_parse_error": True, "_raw": str(raw)[:800]}
    if isinstance(data, dict):
        return data if data else None
    return {"value": data}


def _format_packet_log_row(r: dict) -> dict:
    http_obj = _safe_json_object(r.get("http_json"))
    return {
        "id": r["id"],
        "timestamp": r["timestamp"],
        "src_ip": r["src_ip"],
        "dst_ip": r["dst_ip"],
        "src_port": r["src_port"],
        "dst_port": r["dst_port"],
        "protocol": r["protocol"],
        "duration": r["duration"],
        "packets": r["packets"],
        "bytes": r["bytes"],
        "url": r["url"],
        "http": http_obj,
        "http_json": r.get("http_json"),
        "classification": r["classification"],
        "ai_label": r["ai_label"],
        "confidence": r["confidence"],
        "anomaly_score": r["anomaly_score"],
        "ai_score": r["ai_score"],
        "risk_score": r.get("risk_score"),
        "reasons": _safe_json_reasons(r.get("reasons_json")),
        "ti_ip": _safe_json_object(r.get("ti_ip_json")),
        "ti_url": _safe_json_object(r.get("ti_url_json")),
        "dns": _safe_json_object(r.get("dns_json")),
        "mitre": _safe_json_mitre(r.get("mitre_json")),
    }


@app.route("/ids/log-aggregate")
@login_required
@role_required("admin", "soc")
def ids_log_aggregate():
    """Time-window totals for charts when the sampled log list is sparse or empty."""
    try:
        start_time = request.args.get("start_time", type=float)
        end_time = request.args.get("end_time", type=float)
        payload = aggregate_log_stats(start_time=start_time, end_time=end_time)
        return api_ok(payload)
    except Exception as e:
        return api_error(str(e), status_code=500, code="internal_error")


@app.route("/ids/traffic-timeseries")
@login_required
@role_required("admin", "soc")
def ids_traffic_timeseries():
    """Per-minute severity and risk trend for dashboard charts."""
    try:
        start_time = request.args.get("start_time", type=float)
        end_time = request.args.get("end_time", type=float)
        minutes = request.args.get("minutes", default=60, type=int)
        payload = aggregate_traffic_timeseries(
            start_time=start_time,
            end_time=end_time,
            minutes=minutes,
        )
        return api_ok(payload)
    except Exception as e:
        return api_error(str(e), status_code=500, code="internal_error")


@app.route("/ids/logs")
@login_required
@role_required("admin", "soc")
def get_logs():
    try:
        limit = max(1, min(int(request.args.get("limit", 200)), 1000))
        start_time = request.args.get("start_time", type=float)
        end_time = request.args.get("end_time", type=float)
        min_ai_score = request.args.get("min_ai_score", type=float)
        min_anomaly_score = request.args.get("min_anomaly_score", type=float)
        min_confidence = request.args.get("min_confidence", type=float)
        before_time = request.args.get("before_time", type=float)
        src_ip = request.args.get("src_ip")
        dst_ip = request.args.get("dst_ip")
        ip = request.args.get("ip")
        url = request.args.get("url")
        classification = request.args.get("classification") or request.args.get("status")

        results = query_logs(
            ip=ip,
            src_ip=src_ip,
            dst_ip=dst_ip,
            url=url,
            classification=classification,
            start_time=start_time,
            end_time=end_time,
            min_ai_score=min_ai_score,
            min_anomaly_score=min_anomaly_score,
            min_confidence=min_confidence,
            before_time=before_time,
            limit=limit,
        )

        formatted = [_format_packet_log_row(r) for r in results]

        next_before_time = None
        if formatted:
            next_before_time = formatted[-1]["timestamp"]

        return api_ok(
            formatted,
            meta={
                "limit": limit,
                "next_before_time": next_before_time,
            },
        )
    except Exception as e:
        return api_error(str(e), status_code=500, code="internal_error")


# --- Query historical logs from DB ---
@app.route("/ids/search")
@login_required
@role_required("admin", "soc")
def search_logs_api():
    ip = request.args.get("ip")
    src_ip = request.args.get("src_ip")
    dst_ip = request.args.get("dst_ip")
    port = request.args.get("port", type=int)
    src_port = request.args.get("src_port", type=int)
    dst_port = request.args.get("dst_port", type=int)
    protocol = request.args.get("protocol")
    url = request.args.get("url")
    classification = request.args.get("classification") or request.args.get("status")
    ai_label = request.args.get("ai_label")
    reason = request.args.get("reason")
    has_threat_intel = request.args.get("has_threat_intel")
    limit = max(1, min(int(request.args.get("limit", 200)), 1000))
    start_time = request.args.get("start_time", type=float)
    end_time = request.args.get("end_time", type=float)
    min_ai_score = request.args.get("min_ai_score", type=float)
    max_ai_score = request.args.get("max_ai_score", type=float)
    min_anomaly_score = request.args.get("min_anomaly_score", type=float)
    max_anomaly_score = request.args.get("max_anomaly_score", type=float)
    min_confidence = request.args.get("min_confidence", type=float)
    max_confidence = request.args.get("max_confidence", type=float)
    before_time = request.args.get("before_time", type=float)

    results = query_logs(
        ip=ip,
        src_ip=src_ip,
        dst_ip=dst_ip,
        port=port,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        url=url,
        classification=classification,
        ai_label=ai_label,
        reason=reason,
        has_threat_intel=has_threat_intel,
        start_time=start_time,
        end_time=end_time,
        min_ai_score=min_ai_score,
        max_ai_score=max_ai_score,
        min_anomaly_score=min_anomaly_score,
        max_anomaly_score=max_anomaly_score,
        min_confidence=min_confidence,
        max_confidence=max_confidence,
        before_time=before_time,
        limit=limit,
    )

    formatted = [_format_packet_log_row(r) for r in results]

    next_before_time = None
    if formatted:
        next_before_time = formatted[-1]["timestamp"]

    return api_ok(
        formatted,
        meta={
            "limit": limit,
            "next_before_time": next_before_time,
        },
    )


def _start_ids_sensor_if_enabled() -> None:
    enabled = (os.getenv("WEBUI_START_IDS_SENSOR", "false") or "false").lower() == "true"
    if not enabled:
        return
    try:
        from intelligence.sensor_process import start_sensor_background

        verbose = (os.getenv("IDS_SENSOR_VERBOSE", "false") or "false").lower() == "true"
        start_sensor_background(verbose=verbose)
    except Exception:
        import logging

        logging.getLogger(__name__).error("Failed to start IDS sensor from Web UI", exc_info=True)


if __name__ == "__main__":
    from ai.retrainer import ensure_models_available
    from bootstrap_db import bootstrap_database

    bootstrap_database()

    # Check the AI models are on disk before anything else starts.
    if not ensure_models_available():
        import logging

        logging.getLogger(__name__).error(
            "AI models are not available and could not be trained — refusing to start uni-srver.py."
        )
        raise SystemExit(1)

    try:
        init_persistence()
        sync_stats_from_persistence()
    except Exception:
        import logging
        logging.getLogger(__name__).error("Failed to init IDS persistence", exc_info=True)
    Thread(target=start_retention_worker, daemon=True).start()
    start_analytics_worker_thread()
    _start_ids_sensor_if_enabled()
    use_ssl = (os.getenv("WEB_UI_SSL", "true") or "true").lower() == "true"
    if use_ssl:
        cert_file = os.getenv("SSL_CERT_FILE")
        key_file = os.getenv("SSL_KEY_FILE")
        ssl_context = (cert_file, key_file) if cert_file and key_file else "adhoc"
        app.run(host="0.0.0.0", port=5000, ssl_context=ssl_context)
    else:
        app.run(host="0.0.0.0", port=5000)
