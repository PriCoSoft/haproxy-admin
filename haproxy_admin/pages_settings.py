"""Global settings: timeouts, limits, TLS, listeners, ACME, extra lines and raw sections."""
import copy
import re

from flask import flash, redirect, render_template, request, url_for

from . import model
from .auth import login_required
from .views import S, bp, crt_list_entries, load_state, propose, require_managed


def _lines(text):
    return [l.rstrip() for l in (text or "").replace("\r", "").split("\n") if l.strip()]


def _int(v):
    try:
        return int(str(v).strip())
    except ValueError:
        return -1


@bp.route("/settings")
@login_required
def settings():
    st = load_state()
    m = st.model
    return render_template("settings.html", st=st, m=m, g=m["global"], lis=m["listen"], tls=m["tls"],
                           crt_list=crt_list_entries(), crt_list_path=S().crt_list, acme_port=S().http01_port,
                           raw_text="\n\n".join(m["raw"]), timeout_keys=model.TIMEOUT_ORDER)


@bp.route("/settings", methods=["POST"])
@login_required
def settings_save():
    st = load_state()
    resp = require_managed(st)
    if resp:
        return resp
    if request.form.get("base_sha") != st.sha:
        flash("The configuration changed in the meantime. Please redo your edit.", "error")
        return redirect(url_for("main.settings"))
    f = request.form
    m = copy.deepcopy(st.model)
    g, lis, tls = m["global"], m["listen"], m["tls"]
    g["maxconn"] = _int(f.get("maxconn"))
    g["frontend_maxconn"] = _int(f.get("frontend_maxconn"))
    tos = {}
    for k in model.TIMEOUT_ORDER:
        v = f.get(f"timeout_{k}", "").strip()
        if v:
            tos[k] = v
    for line in _lines(f.get("timeouts_extra")):
        parts = line.split()
        if len(parts) == 2:
            tos[parts[0]] = parts[1]
        else:
            flash(f"Ignored timeout line '{line}' (expected: name value).", "error")
    g["timeouts"] = tos
    g["ssl_options"] = " ".join(f.get("ssl_options", "").split())
    g["ciphers"] = f.get("ciphers", "").strip()
    g["ciphersuites"] = f.get("ciphersuites", "").strip()
    g["dhparam"] = f.get("dhparam", "").strip()
    g["extra_global"] = _lines(f.get("extra_global"))
    g["extra_defaults"] = _lines(f.get("extra_defaults"))
    lis["http_bind"] = f.get("http_bind", "").strip()
    lis["https_bind"] = f.get("https_bind", "").strip()
    lis["h2_port"] = _int(f.get("h2_port"))
    lis["h1_port"] = _int(f.get("h1_port"))
    lis["redirect_to_https"] = bool(f.get("redirect_to_https"))
    lis["acme_http01"] = bool(f.get("acme_http01"))
    tls["source"] = f.get("tls_source", "crt-list")
    tls["files"] = [w for w in re.split(r"\s+", f.get("tls_files", "")) if w]
    if tls["source"] == "crt-list" and not crt_list_entries():
        flash("The crt-list is empty: HTTPS frontends would be left out. Save the crt-list on the Certificates "
              "page first.", "error")
        return redirect(url_for("main.settings"))
    for k in ("http", "https", "tcp"):
        m["extra"][k] = _lines(f.get(f"extra_{k}"))
    raw = f.get("raw", "").replace("\r", "").strip()
    m["raw"] = [b.strip("\n") for b in re.split(r"\n\s*\n(?=\S)", raw) if b.strip()] if raw else []
    resp, errors = propose(m, st.sha, "Change global settings")
    if resp:
        return resp
    for e in errors:
        flash(e, "error")
    return redirect(url_for("main.settings"))
