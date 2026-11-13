"""Security: rate limiting, trusted networks, block list, blocked TLS names, response headers."""
import copy
import ipaddress
import json
import re

from flask import flash, redirect, render_template, request, url_for

from . import model
from .audit import audit
from .auth import login_required
from .views import FE_NAMES, H, RT, S, actor, bp, load_state, propose, require_managed


def read_denylist():
    try:
        with open(S().denylist, encoding="utf-8") as f:
            return [l.strip() for l in f if l.strip() and not l.strip().startswith("#")]
    except OSError:
        return []


def _int(v, default=0):
    try:
        return max(0, int(str(v).strip() or default))
    except ValueError:
        return -1


def _rules(form, prefix):
    out = []
    idx = sorted({int(m.group(1)) for k in form for m in [re.match(rf"^{prefix}(\d{{1,2}})_action$", k)] if m})
    for i in idx:
        a = form.get(f"{prefix}{i}_action", "")
        err, req = _int(form.get(f"{prefix}{i}_err")), _int(form.get(f"{prefix}{i}_req"))
        if not a or (err == 0 and req == 0) or form.get(f"{prefix}{i}_del"):
            continue
        out.append({"action": a, "err_rate": err, "req_rate": req})
    return out


def live_tables():
    """Clients currently tracked by the stick tables, highest error rates first."""
    rows, error = [], None
    try:
        rt = RT()
        for fe in FE_NAMES:
            for e in rt.table(fe):
                e["table"] = fe
                rows.append(e)
    except OSError as e:
        error = f"Runtime API not reachable: {e}"
    rows.sort(key=lambda r: (-r.get("http_err_rate", 0), -r.get("http_req_rate", 0), -r.get("conn_rate", 0)))
    return rows[:60], error


@bp.route("/security")
@login_required
def security():
    st = load_state()
    rows, err = live_tables()
    sec = st.model["security"]
    drop_err = min([r["err_rate"] for r in sec["rules_https"] if r["action"] in ("drop", "deny", "tarpit")
                    and r["err_rate"] and not r["req_rate"]], default=None)
    return render_template("security.html", st=st, m=st.model, sec=sec, hdr=st.model["headers"], live=rows,
                           live_error=err, denylist=read_denylist(), drop_err=drop_err, denylist_path=S().denylist)


@bp.route("/security", methods=["POST"])
@login_required
def security_save():
    st = load_state()
    resp = require_managed(st)
    if resp:
        return resp
    if request.form.get("base_sha") != st.sha:
        flash("The configuration changed in the meantime. Please redo your edit.", "error")
        return redirect(url_for("main.security"))
    f = request.form
    m = copy.deepcopy(st.model)
    sec, hdr = m["security"], m["headers"]
    sec["trusted"] = [w for w in re.split(r"[\s,;]+", f.get("trusted", "")) if w]
    sec["exempt_trusted"] = bool(f.get("exempt_trusted"))
    for k in ("table_size", "table_expire", "http_window", "tcp_window"):
        sec[k] = f.get(k, sec[k]).strip()
    sec["rules_https"] = _rules(f, "rh")
    sec["rules_http"] = _rules(f, "rp")
    sec["tcp_conn_rate"] = _int(f.get("tcp_conn_rate"))
    sec["tcp_conn_cur"] = _int(f.get("tcp_conn_cur"))
    blocks = []
    for i in sorted({int(x.group(1)) for k in f for x in [re.match(r"^sb(\d{1,2})_pattern$", k)] if x}):
        p = f.get(f"sb{i}_pattern", "").strip().lower()
        if p:
            blocks.append({"pattern": p, "except": [w.lower() for w in re.split(r"[\s,;]+", f.get(f"sb{i}_except", "")) if w]})
    sec["sni_block"] = blocks
    hdr["hsts"] = " ".join(f.get("hsts", "").split())
    hdr["hsts_domains"] = [w.lower().lstrip("*.") for w in re.split(r"[\s,;]+", f.get("hsts_domains", "")) if w]
    hdr["frame_options"] = f.get("frame_options", "").strip()
    hdr["nosniff"] = bool(f.get("nosniff"))
    hdr["server"] = f.get("server", "").strip()
    resp, errors = propose(m, st.sha, "Change security settings")
    if resp:
        return resp
    for e in errors:
        flash(e, "error")
    return redirect(url_for("main.security"))


@bp.route("/security/blocklist", methods=["POST"])
@login_required
def blocklist():
    action = request.form.get("action")
    values = [w for w in re.split(r"[\s,;]+", request.form.get("value", "")) if w][:50]
    if action not in ("add", "del") or not values:
        flash("Enter an IP address or network.", "error")
        return redirect(url_for("main.security"))
    for v in values:
        try:
            ipaddress.ip_network(v, strict=False)
        except ValueError:
            flash(f"'{v}' is not a valid IP address or network.", "error")
            return redirect(url_for("main.security"))
    rc, out, err = H().run(["blocklist", action] + values, actor=actor(), timeout=30)
    try:
        result = json.loads(out)
    except ValueError:
        result = {"ok": False, "output": (out + err).strip()}
    audit(f"blocklist.{action}", f"{' '.join(values)} -> {'OK' if result.get('ok') else 'FAILED'}")
    flash(result.get("output", ""), "ok" if result.get("ok") else "error")
    return redirect(url_for("main.security") + "#blocklist")


@bp.route("/security/reset", methods=["POST"])
@login_required
def reset_client():
    table, key = request.form.get("table", ""), request.form.get("key", "")
    try:
        ipaddress.ip_address(key)
    except ValueError:
        flash("Invalid address.", "error")
        return redirect(url_for("main.security"))
    if table not in FE_NAMES:
        flash("Invalid table.", "error")
        return redirect(url_for("main.security"))
    try:
        RT().cmd(f"clear table {table} key {key}")
    except OSError as e:
        flash(f"Runtime API: {e}", "error")
        return redirect(url_for("main.security"))
    audit("table.clear", f"{table} {key}")
    flash(f"Counters for {key} reset in {table}.", "ok")
    return redirect(url_for("main.security") + "#live")
