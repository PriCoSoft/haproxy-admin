"""DNS-01 providers for certbot (--manual-auth-hook / --manual-cleanup-hook), used by haproxy-admin-helper.

Providers (accounts) and their credentials live in STORE (root:root 0600). Secrets are never printed and are
masked in every view handed to the web UI.

Flow per challenge (certbot calls the auth hook once per domain, the cleanup hook afterwards):
  1. pick the provider whose domain list matches CERTBOT_DOMAIN (longest suffix wins)
  2. follow a CNAME on _acme-challenge.<domain> (delegation, e.g. to a dedicated validation zone)
  3. find the authoritative zone of the record (NS walk via public resolvers - split-horizon safe)
  4. create the TXT value with the provider API
  5. poll the authoritative name servers until every one serves the value
  6. after the last challenge wait one TTL, so no resolver can still hold an older copy of the record set
"""
import hashlib
import json
import os
import re
import secrets
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

STORE = "/etc/haproxy-admin/dns-providers.json"
STATE_DIR = "/var/lib/haproxy-admin/dns-state"
PUBLIC_RESOLVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
CF_API = "https://api.cloudflare.com/client/v4"
IONOS_API = "https://api.hosting.ionos.com/dns/v1"
UA = "haproxy-admin-dns/1.0"
TXT_TTL = 60
PROPAGATION_TIMEOUT = 600
POLL_INTERVAL = 5
MAX_EXTRA_WAIT = 330

ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,39}$")
DOMAIN_RE = re.compile(r"^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")

# Provider types. Local plugins (hpa_dns_<name>.py next to this file) can add more via register().
# "mark"/"tone" only drive the badge in the web UI.
TYPES = {
    "cloudflare": {
        "label": "Cloudflare",
        "mark": "CF",
        "tone": "cloudflare",
        "summary": "Cloudflare DNS API with an API token (permissions: Zone → DNS → Edit, Zone → Zone → Read). "
                   "Records are removed again after validation.",
        "cleanup": True,
        "fields": [
            {"key": "api_token", "label": "API token", "secret": True,
             "hint": "My Profile → API Tokens → Create token (template \"Edit zone DNS\")"},
        ],
    },
    "ionos": {
        "label": "IONOS",
        "mark": "IO",
        "tone": "ionos",
        "summary": "IONOS DNS API (developer.hosting.ionos.de) with an API key \"prefix.secret\". "
                   "Records are removed again after validation.",
        "cleanup": True,
        "fields": [
            {"key": "api_key", "label": "API key", "secret": True,
             "hint": "Format <public prefix>.<secret>, created at developer.hosting.ionos.de → API keys"},
        ],
    },
}


class DNSError(Exception):
    pass


def say(msg=""):
    print(msg, flush=True)


# ----------------------------------------------------------------------------- store
def load_store():
    try:
        with open(STORE, encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        data = {}
    data.setdefault("providers", [])
    return data


def save_store(data):
    d = os.path.dirname(STORE)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".dns-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=1, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, STORE)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def secret_keys(ptype):
    return [f["key"] for f in TYPES[ptype]["fields"] if f.get("secret")]


def public_provider(p):
    """Provider without secret values (for the web UI)."""
    q = {k: v for k, v in p.items() if k != "settings"}
    settings = dict(p.get("settings", {}))
    q["secrets_set"] = [k for k in secret_keys(p["type"]) if settings.get(k)]
    for k in secret_keys(p["type"]):
        settings.pop(k, None)
    q["settings"] = settings
    return q


def public_types():
    return TYPES


def validate_provider(new, store):
    """Validate + merge an edited provider (secret fields left empty keep the stored value). Returns the provider."""
    ptype = new.get("type")
    if ptype not in TYPES:
        raise DNSError("Unknown provider type.")
    name = " ".join(str(new.get("name", "")).split())[:60]
    if not name:
        raise DNSError("Enter a name.")
    pid = str(new.get("id") or "").strip().lower()
    old = next((p for p in store["providers"] if p["id"] == pid), None) if pid else None
    if not pid:
        base = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:30] or ptype
        pid, n = base, 2
        while any(p["id"] == pid for p in store["providers"]):
            pid, n = f"{base}-{n}", n + 1
    if not ID_RE.match(pid):
        raise DNSError("Invalid id.")
    domains = []
    for d in new.get("domains", []):
        d = str(d).strip().lower().rstrip(".")
        if d.startswith("*."):
            d = d[2:]
        if not d:
            continue
        if not DOMAIN_RE.match(d):
            raise DNSError(f"Invalid domain '{d}'.")
        if d not in domains:
            domains.append(d)
    if not domains:
        raise DNSError("Enter at least one domain.")
    if len(domains) > 100:
        raise DNSError("Too many domains (max. 100).")
    for p in store["providers"]:
        if p["id"] != pid:
            dup = sorted(set(domains) & set(p.get("domains", [])))
            if dup:
                raise DNSError(f"{', '.join(dup)} already assigned to provider '{p['name']}'.")
    settings = {}
    given = new.get("settings", {}) or {}
    oldset = old.get("settings", {}) if old and old["type"] == ptype else {}
    for f in TYPES[ptype]["fields"]:
        v = str(given.get(f["key"], "") or "").strip()
        if not v and f.get("secret"):
            v = oldset.get(f["key"], "")
        if not v:
            raise DNSError(f"{f['label']} is required.")
        if len(v) > 500 or any(c in v for c in "\r\n\x00"):
            raise DNSError(f"Invalid value for {f['label']}.")
        settings[f["key"]] = v
    if ptype in VALIDATORS:
        VALIDATORS[ptype](settings)
    if ptype == "ionos" and "." not in settings["api_key"]:
        raise DNSError("IONOS API key must have the form prefix.secret")
    return {"id": pid, "type": ptype, "name": name, "domains": domains, "settings": settings,
            "enabled": bool(new.get("enabled", True)), "last_test": (old or {}).get("last_test")}


def find_provider(store, domain):
    domain = domain.lower().rstrip(".")
    if domain.startswith("*."):
        domain = domain[2:]
    best, blen = None, -1
    for p in store["providers"]:
        if not p.get("enabled", True):
            continue
        for d in p.get("domains", []):
            if (domain == d or domain.endswith("." + d)) and len(d) > blen:
                best, blen = p, len(d)
    return best


# ----------------------------------------------------------------------------- DNS lookups (dig)
def dig(name, rtype, server):
    cmd = ["dig", "+noall", "+answer", "+time=3", "+tries=2", f"@{server}", name, rtype]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=20).stdout
    except (OSError, subprocess.TimeoutExpired):
        return None
    rows = []
    for line in out.splitlines():
        parts = line.split(None, 4)
        if len(parts) == 5 and not line.startswith(";"):
            rows.append({"name": parts[0].rstrip(".").lower(), "ttl": int(parts[1]) if parts[1].isdigit() else 0,
                         "type": parts[3].upper(), "data": parts[4].strip()})
    return rows


def public(name, rtype):
    for r in PUBLIC_RESOLVERS:
        rows = dig(name, rtype, r)
        if rows is not None:
            return rows
    return []


def txt_values(rows):
    vals = []
    for r in rows:
        if r["type"] == "TXT":
            vals.append("".join(re.findall(r'"((?:[^"\\]|\\.)*)"', r["data"])) or r["data"])
    return vals


def cname_target(name):
    """Follow CNAMEs (max. 8) via public resolvers. Returns the final name."""
    cur = name.lower().rstrip(".")
    for _ in range(8):
        rows = [r for r in public(cur, "CNAME") if r["type"] == "CNAME" and r["name"] == cur]
        if not rows:
            return cur
        cur = rows[0]["data"].rstrip(".").lower()
    raise DNSError(f"CNAME chain for {name} too long")


def authoritative(name):
    """(zone, [server IPs]) for the zone that contains name (NS walk via public resolvers)."""
    labels = name.lower().rstrip(".").split(".")
    for i in range(len(labels) - 1):
        zone = ".".join(labels[i:])
        ns = [r["data"].rstrip(".") for r in public(zone, "NS") if r["type"] == "NS" and r["name"] == zone]
        if ns:
            ips = []
            for host in ns:
                for r in public(host, "A"):
                    if r["type"] == "A" and r["data"] not in ips:
                        ips.append(r["data"])
            return zone, ns, ips
    raise DNSError(f"No authoritative zone found for {name}")


def wait_visible(fqdn, value, timeout=PROPAGATION_TIMEOUT):
    zone, ns, ips = authoritative(fqdn)
    say(f"  authoritative zone {zone}: {', '.join(ns)} ({', '.join(ips) or 'no address'})")
    if not ips:
        raise DNSError("Name servers of the zone have no IPv4 address")
    deadline = time.time() + timeout
    pending, ttl, unreachable = set(ips), TXT_TTL, set()
    while True:
        for ip in sorted(pending):
            rows = dig(fqdn, "TXT", ip)
            if rows is None:
                unreachable.add(ip)
                continue
            if value in txt_values(rows):
                pending.discard(ip)
                unreachable.discard(ip)
                ttl = max([ttl] + [r["ttl"] for r in rows if r["type"] == "TXT"])
        if not pending:
            say(f"  value visible on all {len(ips)} authoritative server(s), TTL {ttl}s")
            return ttl
        if time.time() > deadline:
            if pending <= unreachable and len(unreachable) < len(ips):
                say(f"  WARNING: {', '.join(sorted(unreachable))} not reachable from here – continuing")
                return ttl
            raise DNSError(f"TXT value not visible on {', '.join(sorted(pending))} after {timeout}s")
        time.sleep(POLL_INTERVAL)


# ----------------------------------------------------------------------------- HTTP
def http(method, url, headers=None, body=None, timeout=30):
    data = None
    h = {"User-Agent": UA, "Accept": "application/json"}
    h.update(headers or {})
    if body is not None:
        if isinstance(body, (dict, list)):
            data = json.dumps(body).encode()
            h["Content-Type"] = "application/json"
        else:
            data = body.encode() if isinstance(body, str) else body
    req = urllib.request.Request(url, data=data, method=method, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except (urllib.error.URLError, OSError) as e:
        raise DNSError(f"connection failed: {getattr(e, 'reason', e)}")


def _json(text):
    try:
        return json.loads(text) if text.strip() else None
    except ValueError:
        return None


# ----------------------------------------------------------------------------- providers
class Cloudflare:
    def __init__(self, p):
        self.h = {"Authorization": f"Bearer {p['settings']['api_token']}"}

    def api(self, method, path, body=None):
        code, text = http(method, CF_API + path, self.h, body)
        data = _json(text)
        if not data or not data.get("success"):
            errs = "; ".join(f"{e.get('code')}: {e.get('message')}" for e in (data or {}).get("errors", [])) \
                or text[:200]
            raise DNSError(f"Cloudflare API {method} {path.split('?')[0]}: HTTP {code} {errs}")
        return data

    def check(self):
        d = self.api("GET", "/user/tokens/verify")
        out = [f"token status: {d['result'].get('status')}"]
        z = self.api("GET", "/zones?per_page=50")
        names = sorted(x["name"] for x in z.get("result", []))
        out.append(f"zones visible to the token: {', '.join(names) or 'none'}")
        return out

    def zone_for(self, fqdn, zone):
        d = self.api("GET", "/zones?" + urllib.parse.urlencode({"name": zone}))
        if not d.get("result"):
            raise DNSError(f"zone {zone} not found in this Cloudflare account (record {fqdn})")
        return d["result"][0]["id"]

    def add(self, fqdn, zone, value):
        zid = self.zone_for(fqdn, zone)
        d = self.api("POST", f"/zones/{zid}/dns_records",
                     {"type": "TXT", "name": fqdn, "content": f'"{value}"', "ttl": TXT_TTL,
                      "comment": "ACME challenge (haproxy-admin)"})
        return {"zone_id": zid, "record_id": d["result"]["id"]}

    def remove(self, fqdn, zone, value, token):
        self.api("DELETE", f"/zones/{token['zone_id']}/dns_records/{token['record_id']}")
        return "record deleted"


class Ionos:
    def __init__(self, p):
        self.h = {"X-API-Key": p["settings"]["api_key"]}

    def api(self, method, path, body=None):
        code, text = http(method, IONOS_API + path, self.h, body)
        if code >= 300:
            data = _json(text)
            msg = text[:200]
            if isinstance(data, list) and data and isinstance(data[0], dict):
                msg = "; ".join(f"{e.get('code')}: {e.get('message')}" for e in data)
            elif isinstance(data, dict):
                msg = data.get("message") or msg
            raise DNSError(f"IONOS API {method} {path}: HTTP {code} {msg}")
        return _json(text)

    def zones(self):
        return self.api("GET", "/zones") or []

    def check(self):
        names = sorted(z["name"] for z in self.zones())
        return [f"zones visible to the key: {', '.join(names) or 'none'}"]

    def zone_for(self, fqdn, zone):
        for z in self.zones():
            if z.get("name", "").lower() == zone:
                return z["id"]
        raise DNSError(f"zone {zone} not found in this IONOS account (record {fqdn})")

    def add(self, fqdn, zone, value):
        zid = self.zone_for(fqdn, zone)
        res = self.api("POST", f"/zones/{zid}/records",
                       [{"name": fqdn, "type": "TXT", "content": value, "ttl": TXT_TTL, "prio": 0, "disabled": False}])
        rid = res[0]["id"] if isinstance(res, list) and res else None
        return {"zone_id": zid, "record_id": rid}

    def remove(self, fqdn, zone, value, token):
        rid = token.get("record_id")
        if not rid:
            for r in (self.api("GET", f"/zones/{token['zone_id']}?recordName={urllib.parse.quote(fqdn)}&recordType=TXT")
                      or {}).get("records", []):
                if r.get("content", "").strip('"') == value:
                    rid = r["id"]
        if not rid:
            return "record not found (already removed?)"
        self.api("DELETE", f"/zones/{token['zone_id']}/records/{rid}")
        return "record deleted"


CLASSES = {"cloudflare": Cloudflare, "ionos": Ionos}


def client(p):
    return CLASSES[p["type"]](p)


# ----------------------------------------------------------------------------- hook flows
def _state_path(domain, value):
    return os.path.join(STATE_DIR, hashlib.sha256(f"{domain}|{value}".encode()).hexdigest()[:32] + ".json")


def set_record(p, domain, value):
    """Create the TXT value for domain; returns (fqdn, zone, token, ttl)."""
    name = "_acme-challenge." + domain
    fqdn = cname_target(name)
    via = f" (CNAME {name} → {fqdn})" if fqdn != name else ""
    say(f"{domain}: provider '{p['name']}' ({TYPES[p['type']]['label']}), record {fqdn}{via}")
    zone, _, _ = authoritative(fqdn)
    token = client(p).add(fqdn, zone, value)
    say("  TXT value created")
    ttl = wait_visible(fqdn, value)
    return fqdn, zone, token, ttl


def hook_auth(env):
    domain = env.get("CERTBOT_DOMAIN", "").lower()
    value = env.get("CERTBOT_VALIDATION", "")
    remaining = int(env.get("CERTBOT_REMAINING_CHALLENGES", "0") or 0)
    if not DOMAIN_RE.match(domain) or not re.match(r"^[A-Za-z0-9_-]{20,128}$", value):
        raise DNSError("CERTBOT_DOMAIN / CERTBOT_VALIDATION missing or invalid")
    store = load_store()
    p = find_provider(store, domain)
    if not p:
        raise DNSError(f"No DNS provider configured for {domain} (Certificates → DNS providers)")
    fqdn, zone, token, ttl = set_record(p, domain, value)
    os.makedirs(STATE_DIR, mode=0o700, exist_ok=True)
    with open(_state_path(domain, value), "w", encoding="utf-8") as f:
        json.dump({"provider": p["id"], "fqdn": fqdn, "zone": zone, "token": token, "ttl": ttl,
                   "created": int(time.time())}, f)
    if remaining == 0:
        wait = min(ttl + 5, MAX_EXTRA_WAIT)
        say(f"last challenge: waiting {wait}s (one TTL) so resolvers drop older copies of the record set")
        time.sleep(wait)


def hook_cleanup(env):
    domain = env.get("CERTBOT_DOMAIN", "").lower()
    value = env.get("CERTBOT_VALIDATION", "")
    path = _state_path(domain, value)
    try:
        with open(path, encoding="utf-8") as f:
            st = json.load(f)
    except (OSError, ValueError):
        say(f"{domain}: nothing to clean up")
        return
    p = next((x for x in load_store()["providers"] if x["id"] == st["provider"]), None)
    try:
        if p:
            say(f"{domain}: {client(p).remove(st['fqdn'], st['zone'], value, st['token'])}")
    except DNSError as e:
        say(f"{domain}: cleanup failed: {e}")
    finally:
        os.unlink(path)


def run_test(p, domain=None):
    """Credential/zone check, delegation check for every domain, optional write test. Returns True if OK."""
    ok = True
    c = client(p)
    say(f"Provider '{p['name']}' ({TYPES[p['type']]['label']})")
    try:
        for line in c.check():
            say("  " + line)
    except DNSError as e:
        say(f"  FAILED: {e}")
        return False
    say("")
    say("Domains:")
    for d in p.get("domains", []):
        name = "_acme-challenge." + d
        try:
            fqdn = cname_target(name)
            zone, ns, _ = authoritative(fqdn)
            via = f"CNAME → {fqdn}" if fqdn != name else "no CNAME"
            c.zone_for(fqdn, zone)
            say(f"  OK    {d}: {via}, zone {zone} ({', '.join(ns)})")
        except DNSError as e:
            ok = False
            say(f"  ERROR {d}: {e}")
    if domain:
        say("")
        value = "hpa-test-" + secrets.token_urlsafe(16)
        say(f"Write test for {domain} (temporary TXT value {value}):")
        try:
            fqdn, zone, token, _ = set_record(p, domain, value)
            say("  " + c.remove(fqdn, zone, value, token))
        except DNSError as e:
            ok = False
            say(f"  FAILED: {e}")
    say("")
    say("RESULT: OK" if ok else "RESULT: FAILED")
    return ok


# ----------------------------------------------------------------------------- local plugins
VALIDATORS = {}
# Optional importer for an existing hook script, set by a plugin:
# {"type": ..., "name": ..., "path": ..., "parse": fn(path) -> settings or None}
LEGACY = None


def register(key, meta, cls, validator=None):
    """Add a provider type (used by local plugins hpa_dns_<name>.py)."""
    TYPES[key] = meta
    CLASSES[key] = cls
    if validator:
        VALIDATORS[key] = validator


def _load_plugins():
    import importlib
    here = os.path.dirname(os.path.abspath(__file__))
    for fn in sorted(os.listdir(here)):
        if re.match(r"^hpa_dns_[a-z0-9_]+\.py$", fn):
            importlib.import_module(fn[:-3])


_load_plugins()
