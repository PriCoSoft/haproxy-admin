"""Smoke test against a managed (generated) config copy: form round trips must give no diff."""
import os
import re
import sys

os.environ.setdefault("BIND", "127.0.0.1:9444")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(__file__))
from haproxy_admin import create_app  # noqa: E402

app = create_app()
c = app.test_client()
fails = 0


from formparse import forms as _forms  # noqa: E402
from werkzeug.datastructures import MultiDict  # noqa: E402


def form_data(html, form_sel=None):
    fs = _forms(html)
    if form_sel == "#siteform":
        f = next(f for f in fs if f["attrs"].get("id") == "siteform")
    elif form_sel:
        f = next(f for f in fs if "form" in f["attrs"].get("class", "") and f["attrs"].get("method") == "post")
    else:
        f = fs[0]
    return MultiDict(f["data"])
def roundtrip(url, form_sel=None, post_url=None):
    global fails
    r = c.get(url)
    data = form_data(r.get_data(as_text=True), form_sel)
    r2 = c.post(post_url or url, data=data, follow_redirects=True)
    t = r2.get_data(as_text=True)
    unchanged = "No differences" in t
    errs = re.findall(r'<div class="flash error">(.*?)</div>', t)
    ok = r2.status_code == 200 and unchanged and not errs
    fails += not ok
    print("OK  " if ok else "FAIL", url, "unchanged" if unchanged else "CHANGED", errs[:3])
    if not ok and not errs:
        print("\n".join(re.findall(r'<span class="(?:add|del)">(.*?)</span>', t))[:3000])


roundtrip("/settings", "form.form")
roundtrip("/security", "form.form", "/security")
html = c.get("/sites").get_data(as_text=True)
for name in sorted(set(re.findall(r'href="/sites/([A-Za-z0-9_.-]+)"', html))):
    if name not in ("new",):
        roundtrip("/sites/" + name, "#siteform")
for u in ["/", "/sites", "/security", "/settings", "/config", "/certs"]:
    r = c.get(u)
    print("OK  " if r.status_code == 200 else "FAIL", r.status_code, u)
print("FAILS:", fails)
