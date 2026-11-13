"""DNS providers for DNS-01 validation (Cloudflare, IONOS, plus optional local plugins).

Credentials are stored by the root helper only (/etc/haproxy-admin/dns-providers.json, 0600). The web app
never reads them back: the helper returns providers with secret fields removed.
"""
import json
import re

from flask import abort, flash, redirect, render_template, request, url_for

from .audit import audit
from .auth import login_required
from .helper import HelperError
from .views import H, _start_helper_job, actor, bp, helper_certs

ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,39}$")


def helper_dns():
    try:
        _, data = H().json(["dns-list"])
        return data, None
    except (HelperError, OSError) as e:
        return None, str(e)


def provider_for(providers, domain):
    d = domain.lower()
    d = d[2:] if d.startswith("*.") else d
    best, blen = None, -1
    for p in providers:
        if not p.get("enabled", True):
            continue
        for z in p.get("domains", []):
            if (d == z or d.endswith("." + z)) and len(z) > blen:
                best, blen = p, len(z)
    return best


def coverage(providers):
    """Domains of DNS-01 certificates + provider domains -> provider."""
    certs, _ = helper_certs()
    rows = {}
    for l in (certs or {}).get("lineages", []):
        if "dns" not in (l.get("challenge") or "") or l.get("staging"):
            continue
        for d in (l.get("cert") or {}).get("sans") or []:
            rows.setdefault(d, {"domain": d, "certs": [], "hook": l.get("dns_hook")})["certs"].append(l["name"])
    for p in providers:
        for z in p.get("domains", []):
            rows.setdefault(z, {"domain": z, "certs": [], "hook": None})
    out = sorted(rows.values(), key=lambda r: (r["domain"].lstrip("*.").split(".")[::-1], r["domain"]))
    for r in out:
        r["provider"] = provider_for(providers, r["domain"])
    return out


@bp.route("/certs/dns")
@login_required
def cert_dns():
    data, err = helper_dns()
    providers = (data or {}).get("providers", [])
    return render_template("dns.html", data=data, err=err, providers=providers,
                           types=(data or {}).get("types", {}), rows=coverage(providers) if data else [])


def _edit_page(p, ptype, types):
    t = types.get(ptype)
    if not t:
        abort(404)
    return render_template("dns_edit.html", p=p, ptype=ptype, t=t)


@bp.route("/certs/dns/new")
@login_required
def cert_dns_new():
    data, err = helper_dns()
    if err:
        flash(f"Helper: {err}", "error")
        return redirect(url_for("main.cert_dns"))
    ptype = request.args.get("type", "")
    t = data["types"].get(ptype)
    if not t:
        abort(404)
    p = {"id": "", "name": t["label"], "domains": [], "enabled": True, "secrets_set": [],
         "settings": {f["key"]: f.get("default", "") for f in t["fields"] if not f.get("secret")}}
    return _edit_page(p, ptype, data["types"])


@bp.route("/certs/dns/<pid>")
@login_required
def cert_dns_edit(pid):
    data, err = helper_dns()
    if err:
        flash(f"Helper: {err}", "error")
        return redirect(url_for("main.cert_dns"))
    p = next((x for x in data["providers"] if x["id"] == pid), None)
    if not p:
        abort(404)
    return _edit_page(p, p["type"], data["types"])


@bp.route("/certs/dns/save", methods=["POST"])
@login_required
def cert_dns_save():
    f = request.form
    data, err = helper_dns()
    if err:
        flash(f"Helper: {err}", "error")
        return redirect(url_for("main.cert_dns"))
    ptype = f.get("type", "")
    t = data["types"].get(ptype)
    if not t:
        abort(400)
    new = {"id": f.get("id", "").strip(), "type": ptype, "name": f.get("name", ""),
           "enabled": bool(f.get("enabled")),
           "domains": [d for d in re.split(r"[\s,;]+", f.get("domains", "")) if d],
           "settings": {fl["key"]: f.get("f_" + fl["key"], "") for fl in t["fields"]}}
    rc, out, errout = H().run(["dns-save"], stdin=json.dumps(new), actor=actor(), timeout=30)
    try:
        res = json.loads(out)
    except ValueError:
        res = {"ok": False, "error": (errout or out).strip()}
    if not res.get("ok"):
        flash(f"Not saved: {res.get('error')}", "error")
        new["secrets_set"] = []
        for k in list(new["settings"]):
            if any(fl["key"] == k and fl.get("secret") for fl in t["fields"]):
                new["settings"][k] = ""
        return _edit_page(new, ptype, data["types"])
    audit("dns.save", f"{res['id']} ({ptype}): {', '.join(new['domains'])}")
    flash(f"Provider '{new['name']}' saved. Run a test to check credentials and delegation.", "ok")
    return redirect(url_for("main.cert_dns") + f"#p-{res['id']}")


@bp.route("/certs/dns/<pid>/delete", methods=["POST"])
@login_required
def cert_dns_delete(pid):
    if not ID_RE.match(pid):
        abort(404)
    rc, out, errout = H().run(["dns-delete", "--id", pid], actor=actor(), timeout=30)
    audit("dns.delete", f"{pid} -> rc={rc}")
    flash("Provider deleted." if rc == 0 else f"Not deleted: {(errout or out).strip()}", "ok" if rc == 0 else "error")
    return redirect(url_for("main.cert_dns"))


@bp.route("/certs/dns/<pid>/test", methods=["POST"])
@login_required
def cert_dns_test(pid):
    if not ID_RE.match(pid):
        abort(404)
    domain = request.form.get("domain", "").strip().lower()
    args = ["dns-test", "--id", pid]
    title = f"Test DNS provider {pid}"
    if domain:
        args += ["--domain", domain]
        title += f" (write test {domain})"
    job = _start_helper_job(title, args)
    return redirect(url_for("main.job", job_id=job.id))


@bp.route("/certs/dns/import-legacy", methods=["POST"])
@login_required
def cert_dns_import():
    rc, out, errout = H().run(["dns-import-legacy"], actor=actor(), timeout=30)
    try:
        res = json.loads(out)
    except ValueError:
        res = {"ok": False, "error": (errout or out).strip()}
    audit("dns.import", f"legacy hook -> {'OK' if res.get('ok') else res.get('error')}")
    if res.get("ok"):
        flash(f"Imported the existing hook script as provider for {', '.join(res['domains'])}.", "ok")
        return redirect(url_for("main.cert_dns") + f"#p-{res['id']}")
    flash(f"Import failed: {res.get('error')}", "error")
    return redirect(url_for("main.cert_dns"))
