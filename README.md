<p align="center"><img src="haproxy_admin/static/icon.svg" width="96" height="96" alt="HAProxy Admin icon"></p>

<h1 align="center">HAProxy Admin</h1>

<p align="center">A small, self-hosted web UI to run an HAProxy reverse proxy and its Let's Encrypt certificates –
directly on the proxy, with distribution packages only.</p>

---

- Runs on the proxy itself (Ubuntu 24.04 / HAProxy 2.8 tested; Debian-based systems with HAProxy ≥ 2.6 should work).
- Python 3 + Flask + gunicorn from the distribution – no pip, no containers, no external web resources.
- Sign-in with **Microsoft Entra ID** (single-tenant app registration, optional per-server app role).
- Every change is **validated (`haproxy -c`) → shown as a diff → applied with backup**, and rolled back automatically
  if the reload fails.

> Not affiliated with or endorsed by HAProxy Technologies. "HAProxy" is a trademark of its respective owner.

## Features

- **Managed configuration** – the complete `haproxy.cfg` is generated from a model (JSON). The model is
  embedded at the end of the file (`#@hpa-model` comment lines), so backups, history, restore and the
  conflict check always cover file and model together. Works on a freshly installed HAProxy as well as on an
  existing hand-written file, which is imported once (*Configuration → Convert*). Manual edits of the file
  are detected and can be imported back into the model.
- **Dashboard** – key figures, "needs attention" (servers down, certificates expiring, host names without
  certificate), recommended setup steps.
- **Sites** – proxy sites (backend + servers) and redirect sites. Per site: host names (exact or wildcard
  patterns) with optional **additional conditions** per host (path begins/is/ends/regex, client IP, method,
  query; negatable), plain-HTTP and HTTP/1.1-only flags, servers (TLS, certificate verification, health
  check), allowed paths, allowed client networks, path redirects, load balancing, sticky cookie, timeouts,
  extra directives; enable/disable, rename, delete. Rules with conditions are evaluated before plain host
  rules, exact hosts before wildcards.
- **Security** – rate limiting / brute-force protection per client IP (thresholds for 4xx error rate and
  request rate, actions drop / 429 / tarpit / log level), TCP connection limits, trusted networks (optionally
  exempt), **block list** (immediate via runtime API, no reload), blocked TLS names (SNI), response headers
  (HSTS incl. restriction to own domains, X-Frame-Options, nosniff, Server). Live view of tracked clients
  with *Reset* and *Block*.
- **Logs** – HAProxy traffic log (parsed: client, host, request, site/server, status, time, termination
  state; search, 4xx/5xx filter, auto refresh) and the haproxy service journal.
- **Certificates** – certbot lineages; request certificates via **DNS-01** (wildcards) or **HTTP-01**
  (customer domains, routed through HAProxy to certbot standalone); staging mode; renew / force renew; deploy
  to HAProxy (`/etc/haproxy/certs/<name>.pem`, 0600, hot-swapped via the runtime API without reload); managed
  crt-list. *Enable auto-deploy* attaches the deploy hook to certificates created outside the tool.
- **DNS providers** – built-in DNS-01 hook with **Cloudflare** (API token) and **IONOS** (DNS API key). Each
  provider serves a list of domains (incl. subdomains). The hook follows `_acme-challenge` CNAMEs, waits until
  all authoritative name servers serve the token and then one TTL (avoids "Incorrect TXT record" on
  back-to-back requests), and removes the record afterwards. *Test* checks credentials, zones and delegation,
  optionally with a temporary write. Credentials are stored root-only and never sent back to the browser.
  Existing certificates are switched with *Switch to built-in DNS hook* (dry run first, restored on error).
  More providers can be added as local plugins (see below).
- **Settings** – listeners, internal ports, certificate source (managed crt-list or fixed files), ACME
  HTTP-01 route, timeouts, limits, TLS protocol settings, extra lines and raw sections for anything else.
- **Configuration / History / Audit** – expert editor for the whole file or single sections, version history
  with diff and restore, audit log of every login and change (the root helper also logs to syslog).

### Generated layout

```
fHTTP-80      :80   rate limits, headers, redirect sites, ACME route, plain-HTTP sites, default -> HTTPS
fTCP-443      :443  block list, connection limits, blocked SNI, SNI of HTTP/1.1-only sites -> bTCP-443-v1,
                    everything else -> bTCP-443           (TLS passthrough, PROXY protocol v2 to loopback)
fHTTP-443-v2  127.0.0.1:8443  TLS termination, h2 + http/1.1, rate limits, headers, all routes
fHTTP-443-v1  127.0.0.1:1443  TLS termination, http/1.1 only (only if a site needs it)
NO-SSL / NO-MATCH / ACME-HTTP01 / one backend per proxy site
```

## Install

### Debian package (recommended)

Download the `.deb` from the [releases](../../releases) and install it with its dependencies:

```bash
sudo apt install ./haproxy-admin_<version>_all.deb
```

The package creates the service user, `/etc/haproxy-admin/` (never overwritten on updates), a temporary
self-signed UI certificate and the systemd service `haproxy-admin`. Build it yourself with
`bash packaging/build-deb.sh` (needs `dpkg-deb`).

### From source

```bash
sudo apt-get install --no-install-recommends python3-flask python3-msal python3-jwt python3-cryptography gunicorn socat
sudo bash install.sh          # keeps an existing /etc/haproxy-admin
```

### First configuration

1. Register an Entra app (below), then fill `tenant_id` and `client_id` in `/etc/haproxy-admin/admin.conf`.
2. Replace the temporary UI certificate (`/etc/haproxy-admin/tls/`), e.g. from your internal CA:
   `/opt/haproxy-admin/bin/import-pfx.sh <file.pfx> [issuing-ca.cer]` – asks for the PFX password, writes
   `cert.pem` (leaf + CA) and `key.pem` and prints the SHA-1 thumbprint.
3. Set the listen address in `/etc/haproxy-admin/service.env` (default `0.0.0.0:9443`) and
   `systemctl restart haproxy-admin`.
4. Open the UI. An existing `haproxy.cfg` is shown read-only until you convert it (*Configuration → Convert*:
   preview → apply).

## Entra ID app registration (single tenant)

1. *App registrations → New registration*: name `HAProxy Admin`, *Single tenant*,
   redirect URI (Web) `https://<server-fqdn>:9443/auth/callback`. One registration can serve several proxies –
   add one redirect URI per server.
2. *Certificates & secrets*: upload the UI certificate (`cert.pem`, leaf only is fine) **or** create a
   client secret (store it in a file, `root:haproxy-admin 0640`, set `client_secret_file`).
3. *App roles* (only if you use per-server roles): create a role with **value = the server's `hostname`
   setting**, allowed member type *Users/Groups*.
4. *Enterprise applications → HAProxy Admin → Properties*: **Assignment required = Yes**.
   *Users and groups*: assign the administrators (with the server role, if roles are used).

If `hostname` is empty, no role is checked – every user who can sign in (i.e. is assigned) is admin.

## Architecture / security model

```
browser ──https:9443──> gunicorn (user haproxy-admin, group haproxy → admin.sock read)
                           │ sudo -n (fixed path, see deploy/sudoers-haproxy-admin)
                           ▼
                        /opt/haproxy-admin/bin/haproxy-admin-helper  (root, fixed sub-commands, validated args)
                           ├─ haproxy -c / write haproxy.cfg / systemctl reload haproxy
                           ├─ certbot certonly|renew|delete|reconfigure (+ DNS-01 and deploy hooks)
                           └─ /etc/haproxy/certs, crt-list, block list, DNS provider store, runtime API
```

- The UI listens on its own port with its own TLS certificate, independent of HAProxy. Expose it to
  internal networks only.
- Editing haproxy.cfg is root-equivalent by nature (e.g. `lua-load`). Only grant access to administrators.
- `auth.mode = none` is refused unless the service binds to a loopback address (tests via SSH tunnel).
- CSRF tokens on all POSTs, strict CSP, no external resources, session lifetime 8 h.

## HTTP-01 for customer domains

Enable *Settings → ACME HTTP-01 challenges* (`/.well-known/acme-challenge/` on port 80 → `127.0.0.1:8402`,
where certbot standalone listens only during validation). The customer's DNS name must point to the proxy.

## Block list

`/etc/haproxy/blocklist.acl` (setting `[haproxy] blocklist`), one address/network per line. The generated
configuration rejects these clients on port 80 and 443. Changes from the Security page are written to the
file and applied to the running HAProxy via the runtime API (`add acl` / `del acl`) – no reload.

## DNS provider plugins

Additional DNS-01 providers can be added without changing the code: put a module `hpa_dns_<name>.py` next to
`/opt/haproxy-admin/bin/hpa_dns.py` (root-owned, mode 0644). It is loaded automatically and registers itself:

```python
import hpa_dns

class MyDNS:
    def __init__(self, provider): self.s = provider["settings"]
    def check(self): return ["credentials ok"]                       # lines shown by "Test"
    def zone_for(self, fqdn, zone): return zone                      # raise hpa_dns.DNSError if not served
    def add(self, fqdn, zone, value): return {"id": "..."}           # create TXT, return cleanup token
    def remove(self, fqdn, zone, value, token): return "deleted"     # delete TXT

hpa_dns.register("mydns", {"label": "My DNS", "mark": "MY", "tone": "accent", "summary": "…", "cleanup": True,
                           "fields": [{"key": "api_key", "label": "API key", "secret": True}]}, MyDNS)
```

`install.sh` installs such plugins from `bin/`; the `.deb` does not contain any.

## Layout on the server

| Path | Purpose |
|---|---|
| `/opt/haproxy-admin/` | code (root-owned) |
| `/etc/haproxy-admin/admin.conf` | settings (see `deploy/admin.conf.example`) |
| `/etc/haproxy-admin/service.env` | listen address and TLS files for gunicorn |
| `/etc/haproxy-admin/tls/` | UI certificate + key |
| `/etc/haproxy-admin/dns-providers.json` | DNS provider accounts incl. credentials (root:root 0600, written only by the helper) |
| `/var/lib/haproxy-admin/backups/` | haproxy.cfg backups (root only) |
| `/var/lib/haproxy-admin/dns-state/` | pending DNS-01 records between auth and cleanup hook |
| `/var/log/haproxy-admin/audit.log` | audit log |
| `/etc/haproxy/certs/` | combined PEMs for HAProxy |
| `/etc/haproxy/blocklist.acl` | blocked client addresses (Security page) |
| `/var/log/haproxy.log` | HAProxy traffic log read by the Logs page (via helper) |

## Tests

Run on a proxy as root; nothing is applied.

- `tests/roundtrip.py <haproxy.cfg> <out-dir>` – import → generate → `haproxy -c` → re-import → identical output.
- `tests/smoke.py`, `tests/smoke_managed.py` – Flask test client: all pages, no-op form round trips
  (needs a configuration copy with `auth.mode = none` and `BIND=127.0.0.1:…`).
- `tests/dns_providers.py` – DNS provider module offline (mock Cloudflare/IONOS APIs, plugin registration, hook flow).

## License

[MIT](LICENSE)
