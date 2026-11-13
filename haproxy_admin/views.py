"""Web UI views: shared helpers, dashboard, configuration, preview/apply, history, certificates."""
import difflib
import hashlib
import json
import re
import secrets
import threading
import time

from flask import (Blueprint, abort, current_app, flash, g, jsonify, redirect, render_template,
                   request, url_for)

from . import cfgparse, importer, jobs, model
from .audit import audit, read_audit
from .auth import login_required
from .helper import HelperError
from .runtime import Runtime, host_covered

bp = Blueprint("main", __name__)

NAME_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{0,62}$")
DOMAIN_RE = re.compile(r"^(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
BACKUP_ID_RE = re.compile(r"^\d{8}T\d{6}Z-[0-9a-f]{8}$")
FE_NAMES = [model.FE_TCP, model.FE_H2, model.FE_H1, model.FE_HTTP]


def S():
    return current_app.extensions["hpa_settings"]


def H():
    return current_app.extensions["hpa_helper"]


def RT():
    return Runtime(S().haproxy_socket)


def actor():
    return g.user.get("upn", "unknown")


def read_cfg():
    with open(S().haproxy_config, "rb") as f:
        data = f.read()
    return data.decode("utf-8", "replace"), hashlib.sha256(data).hexdigest()


def normalize(text):
    t = text.replace("\r\n", "\n").replace("\r", "\n")
    return t if t.endswith("\n") else t + "\n"


# ------------------------------------------------------------------ model handling
def crt_list_entries():
    try:
        with open(S().crt_list, encoding="utf-8") as f:
            return [l.strip() for l in f if l.strip() and not l.strip().startswith("#")]
    except OSError:
        return []


def gen_ctx():
    s = S()
    return {"crt_list": s.crt_list, "crt_list_count": len(crt_list_entries()), "acme_port": s.http01_port,
            "denylist": s.denylist}


class State:
    """Current file + model. managed = the file carries an embedded model."""

    def __init__(self):
        self.text, self.sha = read_cfg()
        m, self.body = model.extract(self.text)
        self.managed = m is not None
        self.report = None
        if self.managed:
            self.model = m
        else:
            self.model, self.report = importer.import_config(self.text, gen_ctx())
        self.drift = self.managed and model.render_body(self.model, gen_ctx()) != self.body


def load_state():
    st = getattr(g, "_hpa_state", None)
    if st is None:
        st = g._hpa_state = State()
    return st


def propose(new_model, base_sha, source, error_endpoint=None, **kw):
    """Validate a changed model, render it and open the preview. Returns a response."""
    errors = model.validate(new_model)
    if errors:
        return None, errors
    text = model.render(new_model, gen_ctx())
    return redirect(url_for("main.preview", cid=put_candidate(text, base_sha, source))), []


def require_managed(st):
    if st.managed:
        return None
    flash("This configuration is not managed by HAProxy Admin yet. Review and apply the conversion first.", "error")
    return redirect(url_for("main.convert"))


# ------------------------------------------------------------------ candidate store
_cands = {}
_cands_lock = threading.Lock()


def put_candidate(content, base_sha, source):
    cid = secrets.token_urlsafe(12)
    now = time.time()
    with _cands_lock:
        for k in [k for k, v in _cands.items() if now - v["created"] > 3600]:
            del _cands[k]
        _cands[cid] = {"content": normalize(content), "base_sha": base_sha, "source": source,
                       "created": now, "user": actor()}
    return cid


def get_candidate(cid):
    with _cands_lock:
        c = _cands.get(cid)
    if not c:
        abort(410, "This change preview has expired. Please start again.")
    return c


def diff_lines(old, new):
    old_l = [l for l in old.split("\n") if not model.is_model_line(l)]
    new_l = [l for l in new.split("\n") if not model.is_model_line(l)]
    out = []
    for line in difflib.unified_diff(old_l, new_l, "current", "candidate", lineterm="", n=3):
        if line.startswith("+++") or line.startswith("---"):
            continue
        kind = "hunk" if line.startswith("@@") else "add" if line.startswith("+") else "del" if line.startswith("-") else "ctx"
        out.append((kind, line))
    return out


# ------------------------------------------------------------------ helpers for pages
def runtime_snapshot():
    data = {"info": {}, "stats": [], "certs": [], "error": None}
    try:
        rt = RT()
        data["info"] = rt.info()
        data["stats"] = rt.stats()
        data["certs"] = rt.ssl_certs()
    except OSError as e:
        data["error"] = f"HAProxy runtime API not reachable: {e}"
    return data


def summarize_stats(stats):
    frontends, backends = [], {}
    for r in stats:
        px, sv = r.get("pxname"), r.get("svname")
        if sv == "FRONTEND":
            frontends.append(r)
            continue
        b = backends.setdefault(px, {"name": px, "status": "", "servers": [], "scur": "0", "stot": "0"})
        if sv == "BACKEND":
            b.update(status=r.get("status", ""), scur=r.get("scur", "0"), stot=r.get("stot", "0"),
                     e5xx=r.get("hrsp_5xx", ""))
        else:
            b["servers"].append({"name": sv, "status": r.get("status", ""), "check": r.get("check_status", ""),
                                 "addr": r.get("addr", ""), "scur": r.get("scur", "0"), "lastchg": r.get("lastchg", "")})
    problems = [(b["name"], s) for b in backends.values() for s in b["servers"]
                if not (s["status"].startswith("UP") or s["status"] in ("no check", "", "MAINT"))]
    return frontends, backends, problems


def helper_certs():
    try:
        _, data = H().json(["certs"])
        return data, None
    except (HelperError, OSError) as e:
        return None, str(e)


def cert_for_host(host, loaded):
    """None = no certificate, '-' = not checkable (pattern), else the certificate dict."""
    if not host or "*" in host.lstrip("*."):
        return "-"
    h = host[2:] if host.startswith("*.") else host
    return next((c for c in loaded if host_covered(("*." + h) if host.startswith("*.") else h, c["sans"])
                 or host_covered(h, c["sans"])), None)


def setup_checks(st, certs):
    m = st.model
    checks = [{
        "key": "managed", "ok": st.managed and not st.drift,
        "title": "Configuration managed by HAProxy Admin" if not st.managed else "Configuration file matches the model",
        "detail": ("The file is hand-written. Convert it once to the model; afterwards everything can be edited here."
                   if not st.managed else "haproxy.cfg was edited by hand after the last change from this tool."),
        "link": url_for("main.convert") if not st.managed else url_for("main.config"),
        "link_label": "Review conversion" if not st.managed else "Open configuration",
    }, {
        "key": "acme", "ok": m["listen"]["acme_http01"],
        "title": "ACME HTTP-01 route on port 80",
        "detail": "Required for certificates of customer domains (HTTP-01). certbot only listens on "
                  f"127.0.0.1:{S().http01_port} while a challenge runs.",
        "link": url_for("main.settings"), "link_label": "Settings",
    }, {
        "key": "crtlist", "ok": m["tls"]["source"] == "crt-list",
        "title": "TLS certificates loaded from the managed crt-list",
        "detail": "Deploy the certificates on the Certificates page, save the crt-list there, then switch the "
                  "certificate source in Settings. Afterwards every site can use its own certificate.",
        "link": url_for("main.settings"), "link_label": "Settings",
    }, {
        "key": "hsts", "ok": not ("preload" in m["headers"]["hsts"] and not m["headers"]["hsts_domains"]),
        "title": "HSTS 'includeSubdomains; preload' limited to own domains",
        "detail": "HSTS preload is sent for every host. Before serving customer domains, restrict it to your own "
                  "domains (Security → Response headers).",
        "link": url_for("main.security"), "link_label": "Security",
    }]
    if certs:
        world = [c["path"] for lin in certs.get("lineages", []) for k in ("legacy", "deployed")
                 for c in [lin.get(k)] if c and c.get("mode") and int(c["mode"], 8) & 0o004]
        checks.append({
            "key": "perm", "ok": not world,
            "title": "PEM files with private keys are not world-readable",
            "detail": ("World-readable: " + ", ".join(world) + ". Run: chmod 600 <file>") if world else "",
        })
    return checks


def all_hosts(m):
    return [r["host"] for s in m["sites"] if s["enabled"] for r in s["routes"]]


# ------------------------------------------------------------------ dashboard
@bp.route("/")
@login_required
def dashboard():
    st = load_state()
    snap = runtime_snapshot()
    fronts, backs, problems = summarize_stats(snap["stats"])
    certs, cert_err = helper_certs()
    hosts = sorted(set(all_hosts(st.model)))
    uncovered = [h for h in hosts if cert_for_host(h, snap["certs"]) is None]
    expiring = sorted([c for c in snap["certs"] if c["days_left"] is not None and c["days_left"] < 30],
                      key=lambda c: c["days_left"])
    checks = setup_checks(st, certs)
    min_days = min([c["days_left"] for c in snap["certs"] if c["days_left"] is not None], default=None)
    return render_template("dashboard.html", snap=snap, problems=problems, backs=backs, fronts=fronts, st=st,
                           checks=checks, open_checks=[c for c in checks if not c["ok"]], cert_err=cert_err,
                           site_count=len([s for s in st.model["sites"] if s["enabled"]]), host_count=len(hosts),
                           uncovered=uncovered, expiring=expiring, min_days=min_days)


# ------------------------------------------------------------------ conversion / drift
@bp.route("/convert")
@login_required
def convert():
    st = load_state()
    if st.managed and not st.drift:
        flash("The configuration is already managed and matches the model.", "ok")
        return redirect(url_for("main.config"))
    if st.managed:
        m, report = importer.import_config(st.body, gen_ctx())
    else:
        m, report = st.model, st.report
    errors = model.validate(m)
    text = model.render(m, gen_ctx())
    return render_template("convert.html", st=st, report=report, errors=errors,
                           diff=diff_lines(st.text, text), managed=st.managed)


@bp.route("/convert", methods=["POST"])
@login_required
def convert_post():
    st = load_state()
    if request.form.get("base_sha") != st.sha:
        flash("The configuration changed in the meantime.", "error")
        return redirect(url_for("main.convert"))
    action = request.form.get("action", "import")
    if action == "regenerate" and st.managed:
        text = model.render(st.model, gen_ctx())
        source = "Regenerate configuration from the model (discard manual edits)"
    else:
        src = st.body if st.managed else st.text
        m, _ = importer.import_config(src, gen_ctx())
        errs = model.validate(m)
        if errs:
            for e in errs:
                flash(e, "error")
            return redirect(url_for("main.convert"))
        text = model.render(m, gen_ctx())
        source = "Import manual edits into the model" if st.managed else "Convert configuration to managed mode"
    return redirect(url_for("main.preview", cid=put_candidate(text, st.sha, source)))


# ------------------------------------------------------------------ configuration
@bp.route("/config")
@login_required
def config():
    st = load_state()
    return render_template("config.html", text=st.text, sha=st.sha, sections=cfgparse.parse_sections(st.body), st=st)


@bp.route("/config/section/<int:idx>", methods=["GET"])
@login_required
def config_section(idx):
    st = load_state()
    secs = cfgparse.parse_sections(st.body)
    if idx < 0 or idx >= len(secs):
        abort(404)
    return render_template("section_edit.html", sec=secs[idx], idx=idx, sha=st.sha)


@bp.route("/config/preview", methods=["POST"])
@login_required
def config_preview():
    base_sha = request.form.get("base_sha", "")
    st = load_state()
    if base_sha != st.sha:
        flash("The configuration changed on disk after you opened the editor. Your edit was not applied; "
              "please redo it on the current version.", "error")
        return redirect(url_for("main.config"))
    tail = st.text[len(st.body):] if st.managed else ""
    if "section" in request.form:
        idx = int(request.form["section"])
        new_text = cfgparse.replace_section(st.body, idx, normalize(request.form.get("content", ""))).rstrip("\n") \
            + "\n" + tail
        source = f"Edit section {cfgparse.parse_sections(st.body)[idx].title}"
    else:
        new_text = request.form.get("content", "")
        source = "Edit full configuration"
    cid = put_candidate(new_text, st.sha, source)
    return redirect(url_for("main.preview", cid=cid))


@bp.route("/preview/<cid>")
@login_required
def preview(cid):
    c = get_candidate(cid)
    current, sha = read_cfg()
    stale = sha != c["base_sha"]
    rc, out, err = H().run(["validate"], stdin=c["content"], actor=actor(), timeout=60)
    m, body = model.extract(c["content"])
    manual = m is not None and model.render_body(m, gen_ctx()) != body
    return render_template("preview.html", cid=cid, c=c, diff=diff_lines(current, c["content"]),
                           valid=(rc == 0), output=(out + err).strip(), stale=stale, manual=manual,
                           unchanged=(current == c["content"]))


@bp.route("/preview/<cid>/edit")
@login_required
def preview_edit(cid):
    c = get_candidate(cid)
    return render_template("config.html", text=c["content"], sha=c["base_sha"], sections=[], from_candidate=True,
                           st=None)


@bp.route("/apply/<cid>", methods=["POST"])
@login_required
def apply(cid):
    c = get_candidate(cid)
    reason = re.sub(r"[\r\n]", " ", request.form.get("reason", "")).strip()[:200] or c["source"]
    rc, out, err = H().run(["apply", "--expect-sha", c["base_sha"], "--reason", reason],
                           stdin=c["content"], actor=actor(), timeout=120)
    try:
        result = json.loads(out)
    except ValueError:
        result = {"ok": False, "stage": "helper", "output": (out + err).strip()}
    audit("config.apply", f"{reason} -> {'OK' if result.get('ok') else 'FAILED (' + result.get('stage', '?') + ')'}")
    if result.get("ok"):
        with _cands_lock:
            _cands.pop(cid, None)
    return render_template("apply_result.html", result=result, reason=reason, cid=cid)


# ------------------------------------------------------------------ history
@bp.route("/history")
@login_required
def history():
    try:
        _, items = H().json(["history"])
    except HelperError as e:
        items = []
        flash(str(e), "error")
    return render_template("history.html", items=items)


@bp.route("/history/<bid>")
@login_required
def history_view(bid):
    if not BACKUP_ID_RE.match(bid):
        abort(404)
    rc, out, err = H().run(["backup-show", bid])
    if rc != 0:
        abort(404)
    current, _ = read_cfg()
    shown = "\n".join(l for l in out.split("\n") if not model.is_model_line(l))
    return render_template("history_view.html", bid=bid, text=shown, diff=diff_lines(current, out))


@bp.route("/history/<bid>/restore", methods=["POST"])
@login_required
def history_restore(bid):
    if not BACKUP_ID_RE.match(bid):
        abort(404)
    rc, out, err = H().run(["backup-show", bid])
    if rc != 0:
        abort(404)
    _, sha = read_cfg()
    return redirect(url_for("main.preview", cid=put_candidate(out, sha, f"Restore backup {bid}")))


# ------------------------------------------------------------------ certificates
@bp.route("/certs")
@login_required
def certs():
    st = load_state()
    data, err = helper_certs()
    snap = runtime_snapshot()
    loaded_paths = {c["path"] for c in snap["certs"]}
    lineages = (data or {}).get("lineages", [])
    for l in lineages:
        paths = [x["path"] for x in (l.get("deployed"), l.get("legacy")) if x]
        l["in_haproxy"] = [p for p in paths if p in loaded_paths]
    deployed = [l["name"] for l in lineages if l.get("deployed")] + [o["name"] for o in (data or {}).get("other", [])]
    return render_template("certs.html", data=data, lineages=lineages, err=err, loaded=snap["certs"],
                           rt_error=snap["error"], jobs=jobs.recent()[:8], crt_list=crt_list_entries(),
                           crt_list_path=S().crt_list, crt_list_active=(st.model["tls"]["source"] == "crt-list"
                                                                        and st.managed), deployed=deployed)


@bp.route("/certs/new", methods=["GET"])
@login_required
def cert_new_form():
    from .pages_dns import helper_dns
    st = load_state()
    dns, dns_err = helper_dns()
    return render_template("cert_new.html", acme_route=st.model["listen"]["acme_http01"] and st.managed,
                           domains=request.args.get("domains", ""), http01_port=S().http01_port,
                           dns=dns or {}, dns_err=dns_err)


def _start_helper_job(title, args):
    user = actor()
    app = current_app._get_current_object()
    helper = H()

    def done(job):
        with app.app_context():
            audit(f"job.{args[0]}", f"{title} -> rc={job.rc}", user={"upn": user})

    audit(f"job.{args[0]}.start", title)
    return jobs.start(title, user, lambda: helper.popen(args, actor=user), on_done=done)


@bp.route("/certs/new", methods=["POST"])
@login_required
def cert_new():
    domains = [d.strip().lower() for d in re.split(r"[\s,;]+", request.form.get("domains", "")) if d.strip()]
    method = request.form.get("method", "dns")
    key_type = request.form.get("key_type", "rsa")
    staging = bool(request.form.get("staging"))
    name = request.form.get("name", "").strip().lower() or (domains[0].lstrip("*.") if domains else "")
    errors = []
    if not domains or len(domains) > 20 or not all(DOMAIN_RE.match(d) for d in domains):
        errors.append("Enter 1-20 valid domain names.")
    if method not in ("dns", "http"):
        errors.append("Invalid validation method.")
    if method == "http" and any(d.startswith("*.") for d in domains):
        errors.append("Wildcard certificates require DNS-01 validation.")
    if key_type not in ("rsa", "ecdsa"):
        errors.append("Invalid key type.")
    if not NAME_RE.match(name):
        errors.append("Invalid certificate name.")
    if errors:
        for e in errors:
            flash(e, "error")
        return redirect(url_for("main.cert_new_form", domains=" ".join(domains)))
    args = ["issue", "--name", name, "--method", method, "--key-type", key_type]
    if staging:
        args.append("--staging")
    for d in domains:
        args += ["-d", d]
    job = _start_helper_job(f"Issue {'STAGING ' if staging else ''}certificate {name} ({', '.join(domains)}) via {method.upper()}-01", args)
    return redirect(url_for("main.job", job_id=job.id))


@bp.route("/certs/<name>/<action>", methods=["POST"])
@login_required
def cert_action(name, action):
    if not NAME_RE.match(name) or action not in ("renew", "force-renew", "deploy", "auto-deploy", "dns-switch", "delete"):
        abort(404)
    if action == "dns-switch":
        args, title = ["dns-switch", "--name", name], f"Switch {name} to the built-in DNS hook (test renewal)"
    elif action == "auto-deploy":
        args, title = ["auto-deploy", "--name", name], f"Enable auto-deploy for {name} (test renewal + deploy)"
    elif action == "renew":
        args, title = ["renew", "--name", name], f"Renew {name} (if due)"
    elif action == "force-renew":
        args, title = ["renew", "--name", name, "--force"], f"Force renew {name}"
    elif action == "deploy":
        args, title = ["deploy", "--name", name], f"Deploy {name} to HAProxy"
    else:
        if request.form.get("confirm", "") != name:
            flash("Type the certificate name to confirm deletion.", "error")
            return redirect(url_for("main.certs"))
        args, title = ["delete", "--name", name], f"Delete {name}"
    job = _start_helper_job(title, args)
    return redirect(url_for("main.job", job_id=job.id))


@bp.route("/certs/crt-list", methods=["POST"])
@login_required
def crt_list_save():
    names = request.form.getlist("active")
    default = request.form.get("default", "")
    if default and default in names:
        names.remove(default)
        names.insert(0, default)
    if not names or not all(NAME_RE.match(n) for n in names):
        flash("Select at least one certificate.", "error")
        return redirect(url_for("main.certs"))
    rc, out, err = H().run(["crtlist-write"] + names, actor=actor(), timeout=120)
    try:
        result = json.loads(out)
    except ValueError:
        result = {"ok": False, "output": (out + err).strip()}
    audit("crtlist.write", f"{', '.join(names)} -> {'OK' if result.get('ok') else 'FAILED'}")
    flash(("crt-list saved. " if result.get("ok") else "crt-list NOT saved: ") + result.get("output", ""),
          "ok" if result.get("ok") else "error")
    return redirect(url_for("main.certs"))


@bp.route("/jobs/<job_id>")
@login_required
def job(job_id):
    j = jobs.get(job_id)
    if not j:
        abort(404)
    return render_template("job.html", job=j)


@bp.route("/jobs/<job_id>.json")
@login_required
def job_json(job_id):
    j = jobs.get(job_id)
    if not j:
        abort(404)
    return jsonify(j.as_dict(since=int(request.args.get("since", 0))))


# ------------------------------------------------------------------ audit
@bp.route("/audit")
@login_required
def audit_log():
    return render_template("audit.html", entries=read_audit())


@bp.app_errorhandler(400)
@bp.app_errorhandler(403)
@bp.app_errorhandler(404)
@bp.app_errorhandler(410)
def http_error(e):
    return render_template("error.html", code=e.code, message=e.description), e.code


def init_app(app):
    from . import pages_dns, pages_logs, pages_security, pages_settings, pages_sites  # noqa: F401  (register routes)
    app.register_blueprint(bp)

    @app.template_filter("ts")
    def ts(value):
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(value)) if value else ""

    app.jinja_env.globals.update(COND_TYPES=model.COND_TYPES, RATE_ACTIONS=model.RATE_ACTIONS,
                                 describe_cond=model.describe_cond)
