"""Microsoft Entra ID sign-in (OIDC auth code flow + PKCE via MSAL) and CSRF protection.

Authorization model:
  * single-tenant app registration, the `tid` claim must match tenant_id
  * if [server] hostname is set, the user needs an app role whose value equals that hostname
  * if hostname is empty, every user that can sign in is an admin -> enable
    "Assignment required" on the Enterprise Application!
"""
import functools
import secrets
import time

from flask import (Blueprint, abort, current_app, g, redirect, render_template, request,
                   session, url_for)

from .audit import audit

bp = Blueprint("auth", __name__, url_prefix="/auth")
LOOPBACK = {"127.0.0.1", "::1"}
CSRF_EXEMPT = set()


def _settings():
    return current_app.extensions["hpa_settings"]


def _msal_app():
    import msal  # imported lazily so auth.mode=none works without msal
    s = _settings()
    return msal.ConfidentialClientApplication(
        s.client_id,
        authority=f"https://login.microsoftonline.com/{s.tenant_id}",
        client_credential=s.client_credential(),
    )


def current_user():
    s = _settings()
    if s.auth_mode == "none":
        if request.remote_addr in LOOPBACK:
            return {"name": "Local (auth disabled)", "upn": "local", "oid": ""}
        return None
    u = session.get("user")
    if not u:
        return None
    if time.time() - u.get("login_at", 0) > s.session_hours * 3600:
        session.clear()
        return None
    return u


def login_required(view):
    @functools.wraps(view)
    def wrapper(*args, **kwargs):
        u = current_user()
        if not u:
            if _settings().auth_mode == "none":
                abort(403)
            nxt = request.full_path if request.method == "GET" else "/"
            return redirect(url_for("auth.login", next=nxt))
        g.user = u
        return view(*args, **kwargs)
    return wrapper


def _safe_next(value):
    if value and value.startswith("/") and not value.startswith("//") and "\\" not in value:
        return value
    return "/"


def csrf_token():
    tok = session.get("csrf")
    if not tok:
        tok = secrets.token_urlsafe(32)
        session["csrf"] = tok
    return tok


@bp.route("/login")
def login():
    if current_user():
        return redirect(_safe_next(request.args.get("next")))
    return render_template("login.html", next=_safe_next(request.args.get("next")),
                           error=request.args.get("error"))


@bp.route("/start")
def start():
    s = _settings()
    if s.auth_mode != "entra":
        abort(404)
    flow = _msal_app().initiate_auth_code_flow(scopes=[], redirect_uri=s.redirect_uri,
                                               prompt="select_account")
    session.clear()
    session["flow"] = flow
    session["next"] = _safe_next(request.args.get("next"))
    return redirect(flow["auth_uri"])


@bp.route("/callback")
def callback():
    s = _settings()
    if s.auth_mode != "entra":
        abort(404)
    flow = session.pop("flow", None)
    nxt = session.pop("next", "/")
    if not flow:
        return redirect(url_for("auth.login", error="Sign-in session expired, please try again."))
    try:
        result = _msal_app().acquire_token_by_auth_code_flow(flow, request.args.to_dict())
    except ValueError:
        return redirect(url_for("auth.login", error="Invalid sign-in response (state mismatch)."))
    if "error" in result:
        current_app.logger.warning("Entra sign-in error: %s %s", result.get("error"), result.get("error_description"))
        return redirect(url_for("auth.login", error=f"Sign-in failed: {result.get('error')}"))

    claims = result.get("id_token_claims") or {}
    user = {
        "name": claims.get("name") or claims.get("preferred_username", "?"),
        "upn": claims.get("preferred_username") or claims.get("upn") or claims.get("oid", "?"),
        "oid": claims.get("oid", ""),
    }
    if claims.get("tid", "").lower() != s.tenant_id.lower():
        audit("login.denied", "wrong tenant", user=user)
        abort(403)
    if s.hostname:
        roles = [r.lower() for r in claims.get("roles", [])]
        if s.hostname.lower() not in roles:
            audit("login.denied", f"missing app role {s.hostname}", user=user)
            return render_template("denied.html", user=user, role=s.hostname), 403

    session.clear()
    session.permanent = True
    user["login_at"] = time.time()
    session["user"] = user
    session["csrf"] = secrets.token_urlsafe(32)
    audit("login", "", user=user)
    return redirect(_safe_next(nxt))


@bp.route("/logout", methods=["POST"])
def logout():
    u = session.get("user")
    if u:
        audit("logout", "", user=u)
    session.clear()
    return redirect(url_for("auth.login", error="You have been signed out."))


def init_app(app):
    app.register_blueprint(bp)
    app.jinja_env.globals["csrf_token"] = csrf_token

    @app.before_request
    def check_csrf():
        if request.method in ("POST", "PUT", "DELETE", "PATCH"):
            sent = request.form.get("_csrf") or request.headers.get("X-CSRF-Token") or ""
            expected = session.get("csrf", "")
            if not expected or not secrets.compare_digest(sent, expected):
                abort(400, "CSRF token missing or invalid. Reload the page and try again.")

    @app.context_processor
    def user_ctx():
        try:
            return {"user": current_user(), "auth_mode": _settings().auth_mode}
        except RuntimeError:
            return {"user": None, "auth_mode": _settings().auth_mode}
