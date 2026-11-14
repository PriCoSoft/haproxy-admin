"""HAProxy Admin - web UI to manage HAProxy sites and certificates."""
import ipaddress
import os
from datetime import timedelta

from flask import Flask

from .settings import Settings

__version__ = "0.4.1"


def _bind_is_loopback(bind):
    host = bind.rsplit(":", 1)[0].strip("[]")
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host == "localhost"


def create_app(settings=None):
    s = settings or Settings()

    if s.auth_mode == "none":
        bind = os.environ.get("BIND", "")
        if not bind or not _bind_is_loopback(bind):
            raise RuntimeError("auth.mode = none is only allowed when BIND is a loopback address")

    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=s.secret_key(),
        SESSION_COOKIE_NAME="haproxy_admin",
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        PERMANENT_SESSION_LIFETIME=timedelta(hours=s.session_hours),
        MAX_CONTENT_LENGTH=4 * 1024 * 1024,
    )
    app.extensions["hpa_settings"] = s

    from .helper import Helper
    app.extensions["hpa_helper"] = Helper(s.helper)

    from . import auth, views
    auth.init_app(app)
    views.init_app(app)

    @app.after_request
    def security_headers(resp):
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
            "frame-ancestors 'none'; form-action 'self' https://login.microsoftonline.com; base-uri 'none'")
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Cache-Control"] = "no-store"
        return resp

    @app.context_processor
    def globals_():
        return {"server_name": s.hostname or s.display_name, "app_version": __version__}

    return app
