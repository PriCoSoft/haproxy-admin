"""Smoke test with the Flask test client (run as root on the proxy; nothing is applied).

HAPROXY_ADMIN_CONF must point to a config copy with [auth] mode = none and helper = dev helper.
"""
import os
import re
import sys

os.environ.setdefault("BIND", "127.0.0.1:9444")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from haproxy_admin import create_app, model  # noqa: E402

app = create_app()
app.config["TESTING"] = True
c = app.test_client()
fails = 0


def check(label, resp, expect=200):
    global fails
    ok = resp.status_code == expect
    fails += not ok
    print(("OK  " if ok else "FAIL"), resp.status_code, label)
    if not ok:
        print(resp.get_data(as_text=True)[:3000])
    return resp


def csrf():
    with c.session_transaction() as s:
        return s.get("_csrf") or s.get("csrf")


site_links = sorted(set(re.findall(r'href="(/sites/[A-Za-z0-9._-]+)"', c.get("/sites").get_data(as_text=True))))
for url in ["/", "/sites", "/sites/new", "/sites/new?type=redirect", "/security", "/logs", "/logs?source=service",
            "/logs?status=4", "/settings", "/config", "/convert", "/history", "/certs", "/certs/new", "/certs/dns",
            "/certs/dns/new?type=cloudflare", "/certs/dns/new?type=ionos", "/audit"] + \
        [u for u in site_links if not u.startswith("/sites/new")][:5]:
    check("GET " + url, c.get(url))

html = c.get("/convert").get_data(as_text=True)
print("convert notes:", re.findall(r'<span class="dot warn"></span><div>(.*?)</div>', html))
print("diff lines:", html.count('class="add"'), "added /", html.count('class="del"'), "removed")
