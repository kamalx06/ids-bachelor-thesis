from flask import Flask, request, redirect, render_template, send_file, session, flash, jsonify, abort, Response
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin, current_user
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.utils import secure_filename
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from argon2.low_level import Type
from datetime import timedelta,datetime,timezone
from threading import Lock
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
import unicodedata
import pyclamd
import imghdr
import json
from storage.memory_store import stats, logs, sync_stats_from_persistence
from storage.mysql_store import (
    aggregate_log_stats,
    aggregate_traffic_timeseries,
    query_logs,
    cleanup_old_logs,
)
from storage.persistence import (
    apply_telemetry_stats,
    init_persistence,
    load_statistics_for_api,
)
from ids.metrics import export_prometheus
from ids.websocket_updates import sse_stream, broadcast
from storage.db import get_session, shutdown_session
from storage.models import User as DbUser
import time

dotenv.load_dotenv()

required_vars = ["FLASK_SECRET", "SMTP_HOST", "SMTP_PORT", "SMTP_USER", "SMTP_PASSWORD", "SMTP_FROM"]

missing = [var for var in required_vars if not os.environ.get(var)]
if missing:
    raise RuntimeError(f"Missing environment variables: {', '.join(missing)}")

for var in required_vars:
    globals()[var] = os.environ.get(var)

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE="Strict",
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=60),
    SESSION_REFRESH_EACH_REQUEST=True,
    MAX_CONTENT_LENGTH=2* 1024 * 1024,
    SECRET_KEY=FLASK_SECRET
)

limiter = Limiter(get_remote_address, app=app, default_limits=["400 per day", "100 per hour"])
ALLOWED_IPS = {
    "192.168.122.1",
    "127.0.0.1",
    "::1",
}
@limiter.request_filter
def whitelist_my_ip():
    return request.remote_addr in ALLOWED_IPS
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

lock = Lock()

ph = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=2,
    type=Type.ID
)

@app.before_request
def strict_request_validation():
    te = request.headers.get("Transfer-Encoding")
    cl = request.headers.get("Content-Length")

    if te and cl:
        return {"error": "bad request"}, 400

    if te and te.lower() != "chunked":
        return {"error": "bad request"}, 400

    if cl:
        try:
            if int(cl) <= 0 or int(cl) > app.config["MAX_CONTENT_LENGTH"]:
                return {"error": "invalid length"}, 413
        except ValueError:
            return {"error": "bad request"}, 400
    if request.method in ("POST", "PUT"):
        if not request.content_type:
            return {"error": "content-type required"}, 400

@app.after_request
def secure_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "script-src 'self' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline'"
    )
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
        if row:
            return User(row.id, row.username, row.password_hash, row.role, row.totp_secret, row.totp_enabled)
        return None
    finally:
        s.close()
    return None


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


def start_retention_worker():
    while True:
        try:
            deleted = cleanup_old_logs(days=7)
            if deleted:
                import logging
                logging.getLogger(__name__).info("Retention cleanup removed %d packet log rows", deleted)
        except Exception:
            import logging
            logging.getLogger(__name__).error("Retention worker failed", exc_info=True)
        time.sleep(3600)


def get_user_totp_enabled(user_id):
    s = get_session()
    try:
        row = s.get(DbUser, int(user_id))
        return bool(row.totp_enabled) if row else False
    finally:
        s.close()


def mask_email(email_value: str) -> str:
    if not email_value or "@" not in email_value:
        return email_value or ""
    name, domain = email_value.split("@", 1)
    if not name:
        return "***@" + domain
    visible = name[0]
    return f"{visible}***@{domain}"


def send_email_otp(to_email: str, code: str, purpose: str = "Login verification") -> None:
    host = SMTP_HOST
    port = SMTP_PORT
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

    with smtplib.SMTP(host, port) as smtp:
        smtp.starttls()
        smtp.login(user, password)
        smtp.send_message(msg)

@app.route("/")
def index():
    if current_user.is_authenticated:
        return redirect("/dashboard")
    return redirect("/login")

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute")
@csrf_protect
def login():
    if request.method == "GET":
        return render_template("login.html")

    def render_login_error(message, status_code=401):
        return render_template("login.html", error=message), status_code

    username = request.form.get("username")
    username = (username or "").strip()

    password = request.form.get("password")
    
    if len(username) > 30 or len(password) > 30:
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
        if datetime.utcnow() < datetime.fromisoformat(locked_until):
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

        if failed_attempts >= 5:
            lock_time = datetime.utcnow() + timedelta(minutes=15)
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

    try:
        if not totp_enabled and not email_otp_enabled:
            pass

        elif totp_enabled and not email_otp_enabled:
            if not otp or not totp_secret:
                return render_login_error(error_msg, 401)
            totp = pyotp.TOTP(totp_secret)
            if not totp.verify(otp, valid_window=1):
                return render_login_error(error_msg, 401)

        elif email_otp_enabled and not totp_enabled:
            if not otp or not email_otp_code or not email_otp_code_expires:
                return render_login_error(error_msg, 401)
            try:
                expires_at = datetime.fromisoformat(email_otp_code_expires)
            except Exception:
                return render_login_error(error_msg, 401)
            if datetime.utcnow() > expires_at or otp != email_otp_code:
                return render_login_error(error_msg, 401)
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
                    return render_login_error(error_msg, 401)
                totp = pyotp.TOTP(totp_secret)
                if not totp.verify(otp, valid_window=1):
                    return render_login_error(error_msg, 401)

            elif otp_method == "email":
                if not otp or not email_otp_code or not email_otp_code_expires:
                    return render_login_error(error_msg, 401)
                try:
                    expires_at = datetime.fromisoformat(email_otp_code_expires)
                except Exception:
                    return render_login_error(error_msg, 401)
                if datetime.utcnow() > expires_at or otp != email_otp_code:
                    return render_login_error(error_msg, 401)
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
                return render_login_error(error_msg, 401)
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

    s = get_session()
    try:
        user = (
            s.query(DbUser)
            .filter(DbUser.username == username)
            .order_by(DbUser.id.desc())
            .first()
        )
        if not user:
            return api_error("Invalid credentials", status_code=401)

        try:
            ph.verify(user.password_hash, password)
        except VerifyMismatchError:
            return api_error("Invalid credentials", status_code=401)

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

    s = get_session()
    try:
        user = (
            s.query(DbUser)
            .filter(DbUser.username == username)
            .order_by(DbUser.id.desc())
            .first()
        )
        if not user:
            return api_error("Invalid credentials", status_code=401)

        try:
            ph.verify(user.password_hash, password)
        except VerifyMismatchError:
            return api_error("Invalid credentials", status_code=401)

        if not user.email or not user.email_otp_enabled:
            return api_error(
                "Email-based OTP is not enabled for this account.", status_code=400
            )

        code = f"{secrets.randbelow(10**6):06d}"
        expires_at = (datetime.utcnow() + timedelta(minutes=5)).isoformat()

        user.email_otp_code = code
        user.email_otp_code_expires = expires_at
        s.commit()

        try:
            send_email_otp(user.email, code, purpose="Login verification")
        except Exception:
            return api_error("Failed to send email code.", status_code=500)

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
            return "User not found", 404
        if user.totp_enabled:
            return "TOTP already enabled", 400
        secret = pyotp.random_base32()
        user.totp_secret = secret
        user.totp_enabled = True
        user.totp_qr_shown = False
        s.commit()
    finally:
        s.close()

    session["show_totp_qr"] = True
    return redirect("/settings")


@app.route("/disable_totp", methods=["POST"])
@login_required
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
        if request.is_json:
            return jsonify({"ok": False, "error": "Missing fields"}), 400
        session["settings_error"] = "Missing fields"
        return redirect("/settings")

    s = get_session()
    try:
        user = s.get(DbUser, int(current_user.id))
    finally:
        # we will keep session open for updates below; closed explicitly on each branch
        pass

    if not user:
        if request.is_json:
            return jsonify({"ok": False, "error": "User not found"}), 404
        session["settings_error"] = "User not found"
        return redirect("/settings")

    password_hash = user.password_hash
    totp_secret = user.totp_secret
    totp_enabled = bool(user.totp_enabled)

    if not totp_enabled:
        if request.is_json:
            return jsonify({"ok": False, "error": "TOTP not enabled"}), 400
        session["settings_error"] = "TOTP not enabled"
        return redirect("/settings")

    try:
        ph.verify(password_hash, password)
    except VerifyMismatchError:
        if request.is_json:
            return jsonify({"ok": False, "error": "Invalid password"}), 400
        session["settings_error"] = "Invalid password"
        return redirect("/settings")

    totp = pyotp.TOTP(totp_secret)
    if not totp.verify(otp):
        if request.is_json:
            return jsonify({"ok": False, "error": "Invalid OTP"}), 400
        session["settings_error"] = "Invalid OTP"
        return redirect("/settings")
    s = get_session()
    try:
        u = s.get(DbUser, int(current_user.id))
        if u:
            u.totp_enabled = False
            u.totp_secret = None
            u.totp_qr_shown = False
            s.commit()
    finally:
        s.close()

    if request.is_json:
        return jsonify({"ok": True}), 200
    return redirect("/settings")


@app.route("/verify_new_totp", methods=["POST"])
@login_required
@csrf_protect
def verify_new_totp():
    data = request.json or {}
    otp = data.get("otp")

    if not otp:
        return jsonify({"ok": False, "error": "Missing OTP"}), 400

    s = get_session()
    try:
        user = s.get(DbUser, int(current_user.id))
        if not user:
            return jsonify({"ok": False, "error": "User not found"}), 404

        if not user.totp_enabled or not user.totp_secret:
            return jsonify({"ok": False, "error": "TOTP not enabled"}), 400

        totp = pyotp.TOTP(user.totp_secret)
        if not totp.verify(otp, valid_window=1):
            user.totp_enabled = False
            user.totp_secret = None
            user.totp_qr_shown = False
            s.commit()
            return jsonify(
                {"ok": False, "error": "Invalid OTP. TOTP has been disabled."}
            ), 200

        return jsonify({"ok": True}), 200
    finally:
        s.close()


@app.route("/change_password", methods=["POST"])
@login_required
@csrf_protect
def change_password():

    current_password = request.form.get("current_password")
    new_password = request.form.get("new_password")

    if not current_password or not new_password:
        totp_enabled = get_user_totp_enabled(current_user.id)
        return render_template(
            "settings.html",
            totp_enabled=totp_enabled,
            error="Missing password fields"
        ), 400

    if len(new_password) < 8:
        totp_enabled = get_user_totp_enabled(current_user.id)
        return render_template(
            "settings.html",
            totp_enabled=totp_enabled,
            error="Password must be at least 8 characters"
        ), 400

    elif len(new_password) > 30:
        totp_enabled = get_user_totp_enabled(current_user.id)
        return render_template(
            "settings.html",
            totp_enabled=totp_enabled,
            error="Password cant be more than 30 characters"
        ), 400

    if current_password == new_password:
        totp_enabled = get_user_totp_enabled(current_user.id)
        return render_template(
            "settings.html",
            totp_enabled=totp_enabled,
            error="Passwords should be different"
        ), 400

    s = get_session()
    try:
        user = s.get(DbUser, int(current_user.id))
        if not user:
            totp_enabled = get_user_totp_enabled(current_user.id)
            return render_template(
                "settings.html",
                totp_enabled=totp_enabled,
                error="User not found"
            ), 404

        try:
            ph.verify(user.password_hash, current_password)
        except VerifyMismatchError:
            totp_enabled = get_user_totp_enabled(current_user.id)
            return render_template(
                "settings.html",
                totp_enabled=totp_enabled,
                error="Current passwors is incorrect"
            ), 403

        user.password_hash = ph.hash(new_password)
        s.commit()
    finally:
        s.close()

    return redirect("/settings")


@app.route("/update_profile", methods=["POST"])
@login_required
@csrf_protect
def update_profile():
    username = (request.form.get("username") or "").strip()
    email = (request.form.get("email") or "").strip() or None
    avatar = request.files.get("avatar")

    if not username:
        session["settings_error"] = "Username is required"
        return redirect("/settings")

    s = get_session()
    try:
        existing = (
            s.query(DbUser)
            .filter(DbUser.username == username, DbUser.id != int(current_user.id))
            .first()
        )
        if existing:
            session["settings_error"] = "Username already taken"
            return redirect("/settings")

        user = s.get(DbUser, int(current_user.id))
        old_username = user.username if user else current_user.username
        old_avatar_path = user.avatar_path if user else None

        avatar_path = old_avatar_path
        if avatar and avatar.filename:
            allowed_mimes = {"image/png", "image/jpeg"}
            if avatar.mimetype not in allowed_mimes:
                session["settings_error"] = "Invalid image type for avatar"
                return redirect("/settings")

        filename = secure_filename(avatar.filename)
        ext = os.path.splitext(filename)[1].lower()
        allowed_exts = {".png", ".jpg", ".jpeg"}
        if not ext or ext not in allowed_exts:
            session["settings_error"] = "Invalid image file extension for avatar"
            return redirect("/settings")

        avatar.stream.seek(0, os.SEEK_END)
        size = avatar.stream.tell()
        avatar.stream.seek(0)
        if size > 2 * 1024 * 1024:
            session["settings_error"] = "Avatar image too large (max 2MB)"
            return redirect("/settings")

        avatar.stream.seek(0)
        file_type = imghdr.what(None, h=avatar.stream.read(512))
        avatar.stream.seek(0)

        if file_type not in {"jpeg", "png"}:
            session["settings_error"] = "Invalid image content"
            return redirect("/settings")
        Image.MAX_IMAGE_PIXELS = 10_000_000
        try:
            avatar.stream.seek(0)
            img = Image.open(avatar.stream)

            if img.width > 2000 or img.height > 2000:
                session["settings_error"] = "Image dimensions too large, maximum is 2000x2000"
                return redirect("/settings")
        except Exception:
            session["settings_error"] = "Uploaded file is not a valid image"
            return redirect("/settings")
        finally:
            avatar.stream.seek(0)

        upload_dir = os.path.join(os.path.dirname(__file__), "uploads", "avatars")
        os.makedirs(upload_dir, exist_ok=True)
        random_name = f"user_{current_user.id}_{username}_{secrets.token_hex(32)}.jpg"
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

        if user:
            user.username = username
            user.email = email
            user.avatar_path = avatar_path
            s.commit()
    finally:
        s.close()

    if username != old_username:
        logout_user()
        return redirect("/login")

    return redirect("/settings")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect("/login")

@app.route("/totp_qr")
@login_required
def totp_qr():
    s = get_session()
    try:
        user = s.get(DbUser, int(current_user.id))
        if not user or not user.totp_secret:
            return "TOTP not enabled", 400
        if user.totp_qr_shown:
            return "TOTP QR code can be shown only once", 400

        uri = pyotp.TOTP(user.totp_secret).provisioning_uri(
            name=current_user.username,
            issuer_name="Kamal-Practical-Work-1",
        )

        img = qrcode.make(uri, box_size=4, border=2)
        buf = io.BytesIO()
        img.save(buf)
        buf.seek(0)

        user.totp_qr_shown = True
        s.commit()
    finally:
        s.close()

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
            return jsonify({"ok": False, "error": "Email not set for your account."}), 400

        email = user.email

        code = f"{secrets.randbelow(10**6):06d}"
        expires_at = (datetime.utcnow() + timedelta(minutes=5)).isoformat()

        user.email_otp_code = code
        user.email_otp_code_expires = expires_at
        s.commit()
    finally:
        s.close()

    try:
        send_email_otp(email, code, purpose="Email-based OTP setup")
    except Exception:
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
            return jsonify({"ok": False, "error": "Email not set for your account."}), 400

        email = user.email
        email_otp_enabled = bool(user.email_otp_enabled)

        if not email_otp_enabled:
            return jsonify({"ok": False, "error": "Email-based OTP is not enabled."}), 400

        code = f"{secrets.randbelow(10**6):06d}"
        expires_at = (datetime.utcnow() + timedelta(minutes=5)).isoformat()

        user.email_otp_code = code
        user.email_otp_code_expires = expires_at
        s.commit()
    finally:
        s.close()

    try:
        send_email_otp(email, code, purpose="Disable email-based OTP")
    except Exception:
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
        return jsonify({"ok": False, "error": "Missing code."}), 400

    s = get_session()
    try:
        user = s.get(DbUser, int(current_user.id))
        if not user:
            return jsonify({"ok": False, "error": "User not found."}), 404

        stored_code = user.email_otp_code
        expires_str = user.email_otp_code_expires

        if not stored_code or not expires_str:
            return jsonify({"ok": False, "error": "No pending email OTP setup."}), 400

        try:
            expires_at = datetime.fromisoformat(expires_str)
        except Exception:
            return jsonify({"ok": False, "error": "Invalid code state."}), 400

        if datetime.utcnow() > expires_at:
            return jsonify({"ok": False, "error": "Code expired."}), 400

        if otp != stored_code:
            return jsonify({"ok": False, "error": "Invalid code."}), 400

        user.email_otp_enabled = True
        user.email_otp_code = None
        user.email_otp_code_expires = None
        s.commit()
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
        return jsonify({"ok": False, "error": "Missing fields."}), 400

    s = get_session()
    try:
        user = s.get(DbUser, int(current_user.id))
        if not user:
            return jsonify({"ok": False, "error": "User not found."}), 404

        password_hash = user.password_hash
        email_otp_enabled = bool(user.email_otp_enabled)
        stored_code = user.email_otp_code
        expires_str = user.email_otp_code_expires

        if not email_otp_enabled:
            return jsonify({"ok": False, "error": "Email-based OTP is not enabled."}), 400

        try:
            ph.verify(password_hash, password)
        except VerifyMismatchError:
            return jsonify({"ok": False, "error": "Invalid password."}), 400

        if not stored_code or not expires_str:
            return jsonify({"ok": False, "error": "No verification code found. Start disable flow again."}), 400

        try:
            expires_at = datetime.fromisoformat(expires_str)
        except Exception:
            return jsonify({"ok": False, "error": "Invalid code state."}), 400

        if datetime.utcnow() > expires_at:
            return jsonify({"ok": False, "error": "Code expired."}), 400

        if otp != stored_code:
            return jsonify({"ok": False, "error": "Invalid code."}), 400

        user.email_otp_enabled = False
        user.email_otp_code = None
        user.email_otp_code_expires = None
        s.commit()
        return jsonify({"ok": True}), 200
    finally:
        s.close()

@app.route("/dashboard")
@login_required
@csrf_protect
@role_required("admin", "soc")
def dashboard():
    return render_template("dashboard.html")

@app.route("/admin")
@login_required
@role_required("admin")
def admin_panel():
    return render_template("admin.html")


@app.route("/admin/api/users", methods=["GET"])
@login_required
@role_required("admin")
def admin_list_users():
    page = max(1, int(request.args.get("page", 1)))
    page_size = max(1, min(int(request.args.get("page_size", 25)), 100))
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
        return jsonify({"ok": False, "error": "Invalid role"}), 400
    if not re.fullmatch(r"[a-zA-Z0-9_-]{3,30}", username or ""):
        return jsonify({"ok": False, "error": "Invalid username"}), 400
    if len(password) < 12 or len(password) > 64:
        return jsonify({"ok": False, "error": "Password must be 12-64 characters"}), 400

    password_hash = ph.hash(password)
    s = get_session()
    try:
        existing = s.query(DbUser).filter(DbUser.username == username).first()
        if existing:
            return jsonify({"ok": False, "error": "Username already exists"}), 400
        user = DbUser(
            username=username,
            password_hash=password_hash,
            role=role,
            email=email,
        )
        s.add(user)
        s.commit()
        return jsonify({"ok": True})
    finally:
        s.close()


@app.route("/admin/api/users/<int:user_id>", methods=["DELETE"])
@login_required
@role_required("admin")
@csrf_protect
def admin_delete_user(user_id: int):
    if int(current_user.id) == int(user_id):
        return jsonify({"ok": False, "error": "You cannot delete your own account."}), 400
    s = get_session()
    try:
        user = s.get(DbUser, int(user_id))
        if not user:
            return jsonify({"ok": False, "error": "User not found"}), 404
        s.delete(user)
        s.commit()
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
    if len(new_password) < 12 or len(new_password) > 64:
        return jsonify({"ok": False, "error": "Password must be 12-64 characters"}), 400

    s = get_session()
    try:
        user = s.get(DbUser, int(user_id))
        if not user:
            return jsonify({"ok": False, "error": "User not found"}), 404
        user.password_hash = ph.hash(new_password)
        user.failed_attempts = 0
        user.locked_until = None
        s.commit()
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
        return jsonify({"ok": False, "error": "Invalid role"}), 400
    if int(current_user.id) == int(user_id) and role != "admin":
        return jsonify({"ok": False, "error": "You cannot remove your own admin role."}), 400

    s = get_session()
    try:
        user = s.get(DbUser, int(user_id))
        if not user:
            return jsonify({"ok": False, "error": "User not found"}), 404
        user.role = role
        s.commit()
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
        return jsonify({"ok": False, "error": "Use Settings to manage your own MFA."}), 400

    s = get_session()
    try:
        user = s.get(DbUser, int(user_id))
        if not user:
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

    if int(current_user.id) == int(user_id) and not locked:
        # unlocking self is fine, locking self is blocked below
        pass

    if int(current_user.id) == int(user_id) and locked:
        return jsonify({"ok": False, "error": "You cannot lock your own account."}), 400

    s = get_session()
    try:
        user = s.get(DbUser, int(user_id))
        if not user:
            return jsonify({"ok": False, "error": "User not found"}), 404

        if locked:
            lock_time = datetime.utcnow() + timedelta(hours=8)
            user.locked_until = lock_time.isoformat()
        else:
            user.locked_until = None
            user.failed_attempts = 0

        s.commit()
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

# --- IDS engine health (dashboard live indicator) ---
@app.route("/ids/health")
@login_required
@role_required("admin", "soc")
def ids_engine_health():
    from intelligence.sensor_process import get_sensor_health

    return api_ok(get_sensor_health())


# --- Sensor telemetry push (ids_engine.py → Web UI stats) ---
@app.route("/ids/update", methods=["POST"])
def ids_sensor_update():
    """
    Receive live counters from the IDS sensor process (api_client.sender).
    Logs are read from MySQL by /ids/logs; this endpoint only syncs stats.
    """
    expected_token = os.environ.get("IDS_SENSOR_TOKEN", "")
    if expected_token:
        if request.headers.get("X-IDS-TOKEN") != expected_token:
            return api_error("unauthorized", status_code=401, code="unauthorized")

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
    payload = load_statistics_for_api()
    sync_stats_from_persistence()
    return api_ok(payload)


@app.route("/ids/stream")
@login_required
@role_required("admin", "soc")
def ids_event_stream():
    return Response(sse_stream(), mimetype="text/event-stream")


@app.route("/metrics")
def prometheus_metrics():
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
        limit = int(request.args.get("limit", 200))
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
    limit = int(request.args.get("limit", 200))
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
    enabled = (os.getenv("WEBUI_START_IDS_SENSOR", "true") or "true").lower() == "true"
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
    from bootstrap_db import bootstrap_database

    bootstrap_database()
    try:
        init_persistence()
        sync_stats_from_persistence()
    except Exception:
        import logging
        logging.getLogger(__name__).error("Failed to init IDS persistence", exc_info=True)
    Thread(target=start_retention_worker, daemon=True).start()
    _start_ids_sensor_if_enabled()
    use_ssl = (os.getenv("WEB_UI_SSL", "true") or "true").lower() == "true"
    if use_ssl:
        app.run(host="0.0.0.0", port=5000, ssl_context="adhoc")
    else:
        app.run(host="0.0.0.0", port=5000)