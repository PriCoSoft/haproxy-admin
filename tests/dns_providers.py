"""Offline tests for bin/hpa_dns.py: provider store/validation, domain matching, Cloudflare/IONOS API calls
against a local mock server, plugin registration (register()), hook auth/cleanup flow with CNAME delegation.
No real DNS or API is touched.

  python3 tests/dns_providers.py
"""
import http.server
import json
import os
import sys
import tempfile
import threading
import urllib.parse

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "bin"))
import hpa_dns as D  # noqa: E402

fails = 0


def check(label, cond, extra=""):
    global fails
    fails += not cond
    print("OK  " if cond else "FAIL", label, extra if not cond else "")


# ----------------------------------------------------------------------------- mock APIs
STATE = {"cf": {}, "ionos": {}, "hook": []}


class Mock(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, obj):
        body = json.dumps(obj).encode() if not isinstance(obj, str) else obj.encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json" if not isinstance(obj, str) else "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(n).decode() if n else ""

    def handle_any(self, method):
        u = urllib.parse.urlsplit(self.path)
        q = urllib.parse.parse_qs(u.query, keep_blank_values=True)
        body = self._body()
        if u.path.startswith("/cf/"):
            if self.headers.get("Authorization") != "Bearer good-token":
                return self._send(403, {"success": False, "errors": [{"code": 9109, "message": "Invalid access token"}]})
            p = u.path[3:]
            if p == "/user/tokens/verify":
                return self._send(200, {"success": True, "result": {"status": "active"}})
            if p == "/zones":
                zones = [{"id": "z1", "name": "customer-a.example"}, {"id": "z2", "name": "example.org"}]
                if "name" in q:
                    zones = [z for z in zones if z["name"] == q["name"][0]]
                return self._send(200, {"success": True, "result": zones})
            if p.startswith("/zones/") and p.endswith("/dns_records") and method == "POST":
                rid = f"r{len(STATE['cf']) + 1}"
                STATE["cf"][rid] = json.loads(body)
                return self._send(200, {"success": True, "result": {"id": rid}})
            if "/dns_records/" in p and method == "DELETE":
                STATE["cf"].pop(p.rsplit("/", 1)[1], None)
                return self._send(200, {"success": True, "result": {}})
        if u.path.startswith("/ionos/"):
            if self.headers.get("X-API-Key") != "pre.secret":
                return self._send(401, [{"code": "UNAUTHORIZED", "message": "Missing or invalid API key."}])
            p = u.path[6:]
            if p == "/zones":
                return self._send(200, [{"id": "i1", "name": "customer-b.example", "type": "NATIVE"}])
            if p == "/zones/i1/records" and method == "POST":
                out = []
                for r in json.loads(body):
                    rid = f"x{len(STATE['ionos']) + 1}"
                    STATE["ionos"][rid] = r
                    out.append(dict(r, id=rid))
                return self._send(201, out)
            if p.startswith("/zones/i1/records/") and method == "DELETE":
                STATE["ionos"].pop(p.rsplit("/", 1)[1], None)
                return self._send(200, "")
        if u.path == "/hook/" and method == "POST":
            STATE["hook"].append(body)
            return self._send(200, "ok")
        return self._send(404, {"success": False, "errors": [{"code": 404, "message": "not found"}]})

    def do_GET(self):
        self.handle_any("GET")

    def do_POST(self):
        self.handle_any("POST")

    def do_DELETE(self):
        self.handle_any("DELETE")


srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Mock)
threading.Thread(target=srv.serve_forever, daemon=True).start()
BASE = f"http://127.0.0.1:{srv.server_address[1]}"
D.CF_API = BASE + "/cf"
D.IONOS_API = BASE + "/ionos"


# ----------------------------------------------------------------------------- test plugin (like hpa_dns_<name>.py)
class WebHook:
    """Minimal provider: POSTs the token to a URL; the record must be a fixed (delegated) name."""

    def __init__(self, p):
        self.s = p["settings"]

    def check(self):
        return [f"url {self.s['url']}"]

    def zone_for(self, fqdn, zone):
        if fqdn != self.s["record"]:
            raise D.DNSError(f"record {fqdn} is not {self.s['record']}")
        return zone

    def add(self, fqdn, zone, value):
        self.zone_for(fqdn, zone)
        code, _ = D.http("POST", self.s["url"], {"Content-Type": "text/plain"}, value)
        if code != 200:
            raise D.DNSError(f"HTTP {code}")
        return {}

    def remove(self, fqdn, zone, value, token):
        return "no cleanup"


def _validate_hook(settings):
    if not settings["url"].startswith(("http://", "https://")):
        raise D.DNSError("URL must start with http(s)://")
    settings["record"] = settings["record"].lower().rstrip(".")


D.register("webhook", {"label": "Web hook", "mark": "WH", "tone": "accent", "summary": "test", "cleanup": False,
                       "fields": [{"key": "url", "label": "URL"}, {"key": "record", "label": "Record"},
                                  {"key": "key", "label": "Key", "secret": True}]}, WebHook, _validate_hook)
check("plugin registered", "webhook" in D.TYPES and D.CLASSES["webhook"] is WebHook)

# DNS is faked: CNAME map, zone map, visibility immediate
CNAMES = {"_acme-challenge.example.net": "token.acme.example.net"}
D.cname_target = lambda name: CNAMES.get(name, name)
ZONES = ["acme.example.net", "customer-a.example", "customer-b.example", "other.example"]


def fake_auth(name):
    for z in sorted(ZONES, key=len, reverse=True):
        if name == z or name.endswith("." + z):
            return z, ["ns1." + z], ["192.0.2.1"]
    raise D.DNSError("no zone")


D.authoritative = fake_auth
D.wait_visible = lambda fqdn, value, timeout=0: 60
SLEPT = []
D.time.sleep = lambda s: SLEPT.append(s)

tmp = tempfile.mkdtemp()
D.STORE = os.path.join(tmp, "dns-providers.json")
D.STATE_DIR = os.path.join(tmp, "state")

# ----------------------------------------------------------------------------- store + validation
store = D.load_store()
check("empty store", store == {"providers": []})
hook = D.validate_provider({"type": "webhook", "name": "Own hook", "domains": ["example.net", "*.x.example.net"],
                            "settings": {"url": BASE + "/hook/", "record": "token.acme.example.net.", "key": "k1"}}, store)
check("id generated from name", hook["id"] == "own-hook", hook["id"])
check("domains normalised", hook["domains"] == ["example.net", "x.example.net"], hook["domains"])
check("plugin validator applied", hook["settings"]["record"] == "token.acme.example.net")
store["providers"].append(hook)
cf = D.validate_provider({"type": "cloudflare", "name": "CF", "domains": ["customer-a.example", "other.example"],
                          "settings": {"api_token": "good-token"}}, store)
store["providers"].append(cf)
io = D.validate_provider({"type": "ionos", "name": "IONOS", "domains": ["customer-b.example"],
                          "settings": {"api_key": "pre.secret"}}, store)
store["providers"].append(io)
D.save_store(store)
check("store mode 0600", oct(os.stat(D.STORE).st_mode & 0o777) == "0o600")

try:
    D.validate_provider({"type": "cloudflare", "name": "CF2", "domains": ["customer-a.example"],
                         "settings": {"api_token": "x"}}, store)
    check("duplicate domain rejected", False)
except D.DNSError as e:
    check("duplicate domain rejected", "already assigned" in str(e))
for bad, why in [({"type": "nope", "name": "x", "domains": ["a.example"]}, "type"),
                 ({"type": "cloudflare", "name": "x", "domains": ["bad domain"], "settings": {"api_token": "t"}}, "domain"),
                 ({"type": "cloudflare", "name": "x", "domains": ["a.example"], "settings": {}}, "secret missing"),
                 ({"type": "ionos", "name": "x", "domains": ["b.example"], "settings": {"api_key": "nodot"}}, "ionos key"),
                 ({"type": "webhook", "name": "x", "domains": ["c.example"],
                   "settings": {"url": "ftp://x/", "record": "r.c.example", "key": "k"}}, "plugin validator")]:
    try:
        D.validate_provider(bad, {"providers": []})
        check(f"invalid rejected ({why})", False)
    except D.DNSError:
        check(f"invalid rejected ({why})", True)

edited = D.validate_provider({"id": "cf", "type": "cloudflare", "name": "CF renamed",
                              "domains": ["customer-a.example", "other.example"], "settings": {"api_token": ""}}, store)
check("secret kept on edit", edited["settings"]["api_token"] == "good-token")
pub = D.public_provider(edited)
check("public view hides secret", "api_token" not in pub["settings"] and pub["secrets_set"] == ["api_token"])
check("public view json has no secret", "good-token" not in json.dumps(pub))

check("match exact", D.find_provider(store, "example.net")["id"] == "own-hook")
check("match wildcard", D.find_provider(store, "*.example.net")["id"] == "own-hook")
check("match subdomain", D.find_provider(store, "a.b.customer-a.example")["id"] == "cf")
check("no partial label match", D.find_provider(store, "xcustomer-a.example") is None)
check("unknown domain", D.find_provider(store, "nowhere.example") is None)

# ----------------------------------------------------------------------------- provider calls
c = D.client(cf)
check("cloudflare check", any("active" in l for l in c.check()))
tok = c.add("_acme-challenge.app.customer-a.example", "customer-a.example", "VALUE1")
check("cloudflare record created", STATE["cf"].get(tok["record_id"], {}).get("content") == '"VALUE1"', STATE["cf"])
check("cloudflare record ttl", STATE["cf"][tok["record_id"]]["ttl"] == 60)
c.remove("_acme-challenge.app.customer-a.example", "customer-a.example", "VALUE1", tok)
check("cloudflare record deleted", tok["record_id"] not in STATE["cf"])
try:
    c.add("_acme-challenge.other.example", "other.example", "V")
    check("cloudflare missing zone error", False)
except D.DNSError as e:
    check("cloudflare missing zone error", "not found in this Cloudflare account" in str(e))
try:
    D.Cloudflare({"settings": {"api_token": "bad"}}).check()
    check("cloudflare bad token error", False)
except D.DNSError as e:
    check("cloudflare bad token error", "Invalid access token" in str(e), str(e))

i = D.client(io)
check("ionos check", "customer-b.example" in i.check()[0])
tok = i.add("_acme-challenge.customer-b.example", "customer-b.example", "VALUE2")
check("ionos record created", STATE["ionos"].get(tok["record_id"], {}).get("content") == "VALUE2")
i.remove("_acme-challenge.customer-b.example", "customer-b.example", "VALUE2", tok)
check("ionos record deleted", not STATE["ionos"])
try:
    D.Ionos({"settings": {"api_key": "x.y"}}).zones()
    check("ionos bad key error", False)
except D.DNSError as e:
    check("ionos bad key error", "HTTP 401" in str(e) and "invalid API key" in str(e), str(e))

# ----------------------------------------------------------------------------- hook flow
env = {"CERTBOT_DOMAIN": "app.customer-a.example", "CERTBOT_VALIDATION": "A" * 43, "CERTBOT_REMAINING_CHALLENGES": "1"}
D.hook_auth(env)
check("hook: record created", len(STATE["cf"]) == 1)
check("hook: no wait before last challenge", SLEPT == [])
env2 = dict(env, CERTBOT_VALIDATION="B" * 43, CERTBOT_REMAINING_CHALLENGES="0")
D.hook_auth(env2)
check("hook: one TTL wait after last challenge", SLEPT == [65], SLEPT)
check("hook: state dir 0700", oct(os.stat(D.STATE_DIR).st_mode & 0o777) == "0o700")
D.hook_cleanup(env)
D.hook_cleanup(env2)
check("hook: records cleaned up", not STATE["cf"], STATE["cf"])
check("hook: state files removed", not os.listdir(D.STATE_DIR))
D.hook_auth({"CERTBOT_DOMAIN": "example.net", "CERTBOT_VALIDATION": "C" * 43, "CERTBOT_REMAINING_CHALLENGES": "0"})
check("hook: plugin provider via CNAME", STATE["hook"] == ["C" * 43], STATE["hook"])
D.hook_cleanup({"CERTBOT_DOMAIN": "example.net", "CERTBOT_VALIDATION": "C" * 43})
try:
    D.hook_auth({"CERTBOT_DOMAIN": "nowhere.example", "CERTBOT_VALIDATION": "D" * 43})
    check("hook: no provider error", False)
except D.DNSError as e:
    check("hook: no provider error", "No DNS provider" in str(e))
try:
    D.hook_auth({"CERTBOT_DOMAIN": "x.example; rm -rf /", "CERTBOT_VALIDATION": "D" * 43})
    check("hook: invalid env rejected", False)
except D.DNSError:
    check("hook: invalid env rejected", True)
check("run_test ok", D.run_test(dict(cf, domains=["customer-a.example"]), "app.customer-a.example") is True)
check("run_test detects missing zone", D.run_test(cf) is False)

srv.shutdown()
print()
print("ALL OK" if not fails else f"{fails} FAILED")
sys.exit(1 if fails else 0)
