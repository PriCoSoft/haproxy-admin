"""Sites: list, create, edit, delete (model based)."""
import copy
import re

from flask import abort, flash, jsonify, redirect, render_template, request, url_for

from . import model
from .auth import login_required
from .views import bp, cert_for_host, load_state, propose, require_managed, runtime_snapshot, summarize_stats

ROUTE_KEY = re.compile(r"^r(\d{1,3})_host$")
COND_KEY = re.compile(r"^r(\d{1,3})_c(\d{1,2})_type$")


def _lines(text):
    return [l.strip() for l in (text or "").replace("\r", "").split("\n") if l.strip()]


def _words(text):
    return [w for w in re.split(r"[\s,;]+", text or "") if w]


def site_from_form(form, base):
    s = copy.deepcopy(base)
    s["name"] = form.get("name", "").strip() or s["name"]
    s["description"] = " ".join(form.get("description", "").split())
    s["enabled"] = bool(form.get("enabled"))
    s["type"] = form.get("type", s["type"]) if form.get("type") in ("proxy", "redirect") else s["type"]
    s["http"] = bool(form.get("http"))
    s["http1"] = bool(form.get("http1"))

    routes = []
    idxs = sorted(int(m.group(1)) for k in form for m in [ROUTE_KEY.match(k)] if m)
    for i in idxs:
        host = form.get(f"r{i}_host", "").strip().lower()
        if not host or form.get(f"r{i}_del"):
            continue
        conds = []
        cidx = sorted(int(m.group(2)) for k in form for m in [COND_KEY.match(k)] if m and int(m.group(1)) == i)
        for j in cidx:
            t = form.get(f"r{i}_c{j}_type", "")
            v = " ".join(form.get(f"r{i}_c{j}_val", "").split())
            if not t or not v:
                continue
            conds.append({"type": t, "value": v, "neg": bool(form.get(f"r{i}_c{j}_neg"))})
        for h in _words(host):
            routes.append({"host": h, "conds": copy.deepcopy(conds)})
    s["routes"] = routes

    if s["type"] == "redirect":
        s["target"] = form.get("target", "").strip()
        s["keep_uri"] = bool(form.get("keep_uri"))
        try:
            s["code"] = int(form.get("code", "302"))
        except ValueError:
            s["code"] = 0
        return s

    servers = []
    sidx = sorted({int(m.group(1)) for k in form for m in [re.match(r"^s(\d{1,3})_name$", k)] if m})
    for i in sidx:
        name, addr = form.get(f"s{i}_name", "").strip(), form.get(f"s{i}_addr", "").strip()
        if not name and not addr:
            continue
        servers.append({"name": name, "address": addr, "tls": bool(form.get(f"s{i}_tls")),
                        "verify": bool(form.get(f"s{i}_verify")), "check": bool(form.get(f"s{i}_check")),
                        "options": " ".join(form.get(f"s{i}_opts", "").split())})
    s["servers"] = servers
    s["allow_paths"] = _lines(form.get("allow_paths"))
    s["allow_src"] = _words(form.get("allow_src"))
    redirects = []
    ridx = sorted({int(m.group(1)) for k in form for m in [re.match(r"^rd(\d{1,3})_path$", k)] if m})
    for i in ridx:
        p, to = form.get(f"rd{i}_path", "").strip(), form.get(f"rd{i}_to", "").strip()
        if not p and not to:
            continue
        try:
            code = int(form.get(f"rd{i}_code", "302"))
        except ValueError:
            code = 0
        redirects.append({"path": p, "match": form.get(f"rd{i}_match", "exact"), "to": to, "code": code})
    s["redirects"] = redirects
    s["balance"] = form.get("balance", "leastconn")
    s["keepalive"] = bool(form.get("keepalive"))
    s["prefer_last"] = bool(form.get("prefer_last"))
    s["cookie"] = form.get("cookie", "").strip()
    s["timeout_server"] = form.get("timeout_server", "").strip()
    s["timeout_tunnel"] = form.get("timeout_tunnel", "").strip()
    s["srvtcpka"] = bool(form.get("srvtcpka"))
    s["block"] = bool(form.get("block"))
    s["extra"] = _lines(form.get("extra"))
    return s


def _decorate(m, snap):
    _, backs, _ = summarize_stats(snap["stats"])
    rows = []
    for s in m["sites"]:
        b = backs.get(s["name"])
        st = {x["name"]: x for x in (b["servers"] if b else [])}
        hosts = {}
        for r in s["routes"]:
            h = hosts.setdefault(r["host"], {"host": r["host"], "conds": [], "cert": None})
            if r["conds"]:
                h["conds"].append(" and ".join(model.describe_cond(c) for c in r["conds"]))
            else:
                h["plain"] = True
        for h in hosts.values():
            c = cert_for_host(h["host"], snap["certs"])
            h["cert"] = "-" if c == "-" else c
        rows.append({"site": s, "hosts": list(hosts.values()),
                     "servers": [dict(v, status=st.get(v["name"], {}).get("status", "")) for v in s["servers"]]})
    return rows


@bp.route("/sites")
@login_required
def sites():
    st = load_state()
    snap = runtime_snapshot()
    rows = _decorate(st.model, snap)
    return render_template("sites.html", rows=rows, st=st, rt_error=snap["error"])


def _render_edit(site, st, new, errors, snap=None):
    snap = snap or runtime_snapshot()
    row = _decorate({"sites": [site]}, snap)[0]
    status = {v["name"]: v["status"] for v in row["servers"]}
    certs = {h["host"]: h["cert"] for h in row["hosts"]}
    return render_template("site_edit.html", site=site, new=new, errors=errors, sha=st.sha, st=st,
                           status=status, certs=certs, hsts_all=not st.model["headers"]["hsts_domains"]
                           and bool(st.model["headers"]["hsts"]))


@bp.route("/sites/new", methods=["GET", "POST"])
@login_required
def site_new():
    st = load_state()
    site = model.new_site()
    site["type"] = request.args.get("type", "proxy") if request.args.get("type") in ("proxy", "redirect") else "proxy"
    site["allow_paths"] = []
    if request.args.get("host"):
        site["routes"] = [{"host": request.args["host"].lower(), "conds": []}]
    if request.method == "GET":
        return _render_edit(site, st, True, [])
    resp = require_managed(st)
    if resp:
        return resp
    s = site_from_form(request.form, site)
    if not s["name"] and s["routes"]:
        s["name"] = model.suggest_name(s["routes"][0]["host"])
    errors = []
    if request.form.get("base_sha") != st.sha:
        errors.append("The configuration changed in the meantime. Please check and submit again.")
    else:
        m = copy.deepcopy(st.model)
        m["sites"].append(s)
        resp, errors = propose(m, st.sha, f"New site {s['name']} ({', '.join(r['host'] for r in s['routes'])})")
        if resp:
            return resp
    return _render_edit(s, st, True, errors)


@bp.route("/sites/<name>", methods=["GET", "POST"])
@login_required
def site_edit(name):
    st = load_state()
    site = model.site_by_name(st.model, name)
    if site is None:
        abort(404)
    if request.method == "GET":
        return _render_edit(site, st, False, [])
    resp = require_managed(st)
    if resp:
        return resp
    s = site_from_form(request.form, site)
    errors = []
    if request.form.get("base_sha") != st.sha:
        errors.append("The configuration changed in the meantime. Please reload the page and redo your edit.")
    else:
        m = copy.deepcopy(st.model)
        m["sites"] = [s if x["name"] == name else x for x in m["sites"]]
        label = f"Edit site {name}" + (f" (renamed to {s['name']})" if s["name"] != name else "")
        resp, errors = propose(m, st.sha, label)
        if resp:
            return resp
    return _render_edit(s, st, False, errors)


@bp.route("/sites/<name>/delete", methods=["POST"])
@login_required
def site_delete(name):
    st = load_state()
    resp = require_managed(st)
    if resp:
        return resp
    if model.site_by_name(st.model, name) is None:
        abort(404)
    m = copy.deepcopy(st.model)
    m["sites"] = [x for x in m["sites"] if x["name"] != name]
    resp, errors = propose(m, st.sha, f"Delete site {name}")
    if resp:
        return resp
    for e in errors:
        flash(e, "error")
    return redirect(url_for("main.site_edit", name=name))


@bp.route("/sites/<name>/toggle", methods=["POST"])
@login_required
def site_toggle(name):
    st = load_state()
    resp = require_managed(st)
    if resp:
        return resp
    m = model.normalize(st.model)
    s = model.site_by_name(m, name)
    if s is None:
        abort(404)
    s["enabled"] = not s["enabled"]
    resp, errors = propose(m, st.sha, f"{'Enable' if s['enabled'] else 'Disable'} site {name}")
    if resp:
        return resp
    for e in errors:
        flash(e, "error")
    return redirect(url_for("main.site_edit", name=name))


@bp.route("/sites/suggest-name")
@login_required
def suggest_backend():
    host = (request.args.get("host", "").strip().lower().split() or [""])[0]
    return jsonify({"name": model.suggest_name(host) if host else ""})
