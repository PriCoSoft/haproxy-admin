"""Import an existing (hand-written or generated) haproxy.cfg into the model.

Everything that is understood becomes structured model data; lines that are not understood
are kept as "extra" lines of the matching place or as raw sections, and are reported.
"""
import re

from . import cfgparse
from .model import (COND_TYPES, DEFAULTS_FIXED, ERRORFILES, GLOBAL_FIXED, RATE_ACTIONS, default_model,
                    new_site, normalize)

HOST_FETCHES = {"var(req.host)", "var(txn.host)", "req_ssl_sni", "req.ssl_sni", "hdr(host)", "req.hdr(host)",
                "ssl_fc_sni"}
ACTION_BY_TEXT = {v[1]: k for k, v in RATE_ACTIONS.items()}
ACME_COND = "{ path_beg /.well-known/acme-challenge/ }"


def _norm(line):
    return " ".join(line.split())


# ----------------------------------------------------------------------------- conditions
def parse_terms(cond, acls):
    """AND-only condition -> list of (neg, [expr, ...]) ; None if not understood (OR etc.)."""
    toks = cond.split()
    terms, i = [], 0
    while i < len(toks):
        t, neg = toks[i], False
        if t in ("||", "or"):
            return None
        if t.startswith("!"):
            neg, t = True, t[1:]
            if t == "":
                i += 1
                if i >= len(toks):
                    return None
                t = toks[i]
        if t == "{":
            try:
                j = toks.index("}", i + 1)
            except ValueError:
                return None
            terms.append((neg, [" ".join(toks[i + 1:j])]))
            i = j + 1
        else:
            if t not in acls:
                return None
            terms.append((neg, acls[t]))
            i += 1
    return terms


def _flags(toks):
    """fetch -i -m X values -> (fetch, method, values, has_file)"""
    fetch, method, vals, has_file, i = toks[0], None, [], False, 1
    while i < len(toks):
        t = toks[i]
        if t == "-i":
            i += 1
        elif t == "-m" and i + 1 < len(toks):
            method = toks[i + 1]
            i += 2
        elif t == "-f":
            has_file = True
            i += 2
        elif t == "--":
            vals += toks[i + 1:]
            break
        else:
            vals.append(t)
            i += 1
    return fetch, method, vals, has_file


def _regex_to_glob(rx):
    if not (rx.startswith("^") and rx.endswith("$")):
        return None
    body = rx[1:-1]
    parts = body.split(".*")
    out = []
    for p in parts:
        q = p.replace("[.]", ".").replace("\\.", ".")
        if re.search(r"[\[\]\\()+?{}|^$]", q):
            return None
        out.append(q)
    return "*".join(out).lower()


def host_of(expr):
    """Return a list of host glob patterns for a host expression, or None."""
    toks = expr.split()
    if not toks or toks[0] not in HOST_FETCHES:
        return None
    _, method, vals, has_file = _flags(toks)
    if has_file or not vals:
        return None
    method = method or "str"
    out = []
    for v in vals:
        v = v.lower()
        if method == "str":
            out.append(v)
        elif method == "beg":
            out.append(v + "*")
        elif method == "end":
            out.append("*" + v)
        elif method == "reg":
            g = _regex_to_glob(v)
            if g is None:
                return None
            out.append(g)
        else:
            return None
    return out


def cond_of(expr):
    toks = expr.split()
    if not toks:
        return None
    fetch, method, vals, has_file = _flags(toks)
    if has_file or not vals:
        return None
    t = None
    if fetch == "path":
        t = {"beg": "path_beg", "end": "path_end", "reg": "path_reg", None: "path", "str": "path"}.get(method)
    elif fetch in ("path_beg", "path_end", "path_reg") and method is None:
        t = fetch
    elif fetch == "src" and method is None:
        t = "src"
    elif fetch == "method" and method is None:
        t = "method"
    elif fetch == "query" and method == "sub":
        t = "query"
    if t is None:
        return None
    if t not in ("src", "method") and len(vals) != 1:
        return None
    return {"type": t, "value": " ".join(vals), "neg": False}


def split_route(terms):
    """terms -> (host, conds) or None. Supports host == beg+end combination."""
    hosts, conds = [], []
    for neg, exprs in terms:
        if len(exprs) != 1:
            return None
        h = host_of(exprs[0])
        if h is not None and not neg:
            if len(h) != 1:
                return None
            hosts.append(h[0])
            continue
        c = cond_of(exprs[0])
        if c is None:
            return None
        c["neg"] = neg
        conds.append(c)
    if len(hosts) == 1:
        return hosts[0], conds
    if len(hosts) == 2 and hosts[0].endswith("*") and hosts[1].startswith("*"):
        return hosts[0] + hosts[1][1:].lstrip("*"), conds
    return None


# ----------------------------------------------------------------------------- sections
def _body(sec, lines):
    out = []
    for i in range(sec.header + 1, sec.end):
        s = lines[i].strip()
        if s and not s.startswith("#"):
            out.append(_norm(s))
    return out


def _lead_comment(sec, lines):
    parts = [l.strip().lstrip("#").strip() for l in lines[sec.start:sec.header]]
    return " ".join(p for p in parts if p)


def _bind_info(body):
    for s in body:
        if s.startswith("bind "):
            return s[5:].strip()
    return ""


def _port(addr):
    m = re.search(r":(\d+)$", addr)
    return int(m.group(1)) if m else None


def import_config(text, ctx):
    """Return (model, report). report: {'notes': [...], 'unmapped': [...]}"""
    m = default_model()
    m["sites"], m["raw"] = [], []
    m["security"]["trusted"], m["security"]["sni_block"] = [], []
    m["security"]["rules_https"], m["security"]["rules_http"] = [], []
    m["security"]["exempt_trusted"] = False
    m["headers"].update(server="", hsts="", frame_options="", nosniff=False)
    m["listen"]["acme_http01"] = False
    m["tls"] = {"source": "files", "files": []}
    notes, unmapped = [], []
    lines = text.split("\n")
    secs = cfgparse.parse_sections(text)

    def unknown(where, line, bucket):
        bucket.append(line)
        unmapped.append(f"{where}: {line}")

    # first pass: classify sections
    fronts = {}
    backs = {}
    for sec in secs:
        body = _body(sec, lines)
        if sec.kind == "frontend":
            fronts[sec.name] = (sec, body)
        elif sec.kind == "backend":
            backs[sec.name] = (sec, body)

    def backend_servers(name):
        return [s.split() for s in backs.get(name, (None, []))[1] if s.startswith("server ")]

    fe_http = fe_tcp = fe_h2 = fe_h1 = None
    for name, (sec, body) in fronts.items():
        mode = next((s.split()[1] for s in body if s.startswith("mode ") and len(s.split()) > 1), "http")
        bind = _bind_info(body)
        if mode == "tcp" and fe_tcp is None:
            fe_tcp = name
        elif mode == "http" and " ssl " in f" {bind} ":
            if "h2" in bind and fe_h2 is None:
                fe_h2 = name
            elif fe_h1 is None and "h2" not in bind:
                fe_h1 = name
        elif mode == "http" and fe_http is None:
            fe_http = name
    used_fronts = {x for x in (fe_http, fe_tcp, fe_h2, fe_h1) if x}

    # global
    g = m["global"]
    fixed_g = {_norm(x) for x in GLOBAL_FIXED}
    for sec in secs:
        if sec.kind != "global":
            continue
        for s in _body(sec, lines):
            tok = s.split()
            if _norm(s) in fixed_g:
                continue
            if tok[0] == "ssl-default-bind-ciphers" and len(tok) > 1:
                g["ciphers"] = tok[1]
            elif tok[0] == "ssl-default-bind-ciphersuites" and len(tok) > 1:
                g["ciphersuites"] = tok[1]
            elif tok[0] == "ssl-default-bind-options":
                g["ssl_options"] = " ".join(tok[1:])
            elif tok[0] == "ssl-dh-param-file" and len(tok) > 1:
                g["dhparam"] = tok[1]
            else:
                unknown("global", s, g["extra_global"])
    g["dhparam"] = g["dhparam"] if any(s.kind == "global" and "ssl-dh-param-file" in "\n".join(s.lines)
                                       for s in secs) else ""
    # defaults
    fixed_d = {_norm(x) for x in DEFAULTS_FIXED} | {f"errorfile {c} /etc/haproxy/errors/{c}.http" for c in ERRORFILES}
    timeouts = {}
    for sec in secs:
        if sec.kind != "defaults":
            continue
        for s in _body(sec, lines):
            tok = s.split()
            if _norm(s) in fixed_d:
                continue
            if tok[0] == "timeout" and len(tok) == 3:
                timeouts[tok[1]] = tok[2]
            elif tok[0] == "maxconn" and len(tok) == 2 and tok[1].isdigit():
                g["maxconn"] = int(tok[1])
            else:
                unknown("defaults", s, g["extra_defaults"])
    if timeouts:
        g["timeouts"] = timeouts

    # frontends
    sec_m = m["security"]
    routes = {}         # backend -> list of (host, conds, where)
    redirects = []      # (code, location, host, conds, where)
    h1_sni = []
    tcp_backends = set()

    def table_window(s):
        mm = re.search(r"store\s+\S*?(?:http_err_rate|conn_rate)\((\w+)\)", s)
        size = re.search(r"size\s+(\S+)", s)
        exp = re.search(r"expire\s+(\S+)", s)
        return (mm.group(1) if mm else None, size.group(1) if size else None, exp.group(1) if exp else None)

    def parse_rate(s, acls):
        mm = re.match(r"http-request\s+(.+?)\s+if\s+(.*)$", s)
        if not mm or mm.group(1) not in ACTION_BY_TEXT:
            return None
        terms = parse_terms(mm.group(2), acls)
        if terms is None:
            return None
        rule, exempt = {"action": ACTION_BY_TEXT[mm.group(1)], "err_rate": 0, "req_rate": 0}, False
        for neg, exprs in terms:
            e = " ".join(exprs)
            r = re.match(r"^(?:src|sc0)_http_(err|req)_rate(?:\(\))?\s+gt\s+(\d+)$", e)
            if r and not neg:
                rule[r.group(1) + "_rate"] = int(r.group(2))
            elif neg and exprs == acls.get("__trusted__"):
                exempt = True
            else:
                return None
        return rule, exempt

    def http_frontend(name, kind):
        sec, body = fronts[name]
        acls = {}
        extra = m["extra"]["http" if kind == "http" else "https"]
        rules = []
        for s in body:
            tok = s.split()
            w = tok[0]
            if w == "acl" and len(tok) >= 3:
                acls.setdefault(tok[1], []).append(" ".join(tok[2:]))
                if tok[2] == "src" and tok[1] in ("trusted", "wl", "whitelist", "allowlist"):
                    acls["__trusted__"] = [" ".join(tok[2:])]
                    for v in tok[3:]:
                        if v not in sec_m["trusted"]:
                            sec_m["trusted"].append(v)
                continue
            if w in ("mode", "option") and _norm(s) in (
                    "mode http", "option httplog", "option forwardfor", "option http-server-close",
                    "option httpclose", "option http-no-delay"):
                continue
            if _norm(s) in ("capture request header Host len 128", "tcp-request connection track-sc0 src",
                            "http-request set-header X-Real-IP %[src]"):
                continue
            if w == "bind":
                b = s[5:].strip()
                if kind == "http":
                    m["listen"]["http_bind"] = b.split()[0]
                else:
                    port = _port(b.split()[0])
                    m["listen"]["h2_port" if kind == "h2" else "h1_port"] = port or m["listen"]["h2_port"]
                    if kind == "h2":
                        crts = re.findall(r"(?:^|\s)crt\s+(\S+)", b)
                        lst = re.search(r"crt-list\s+(\S+)", b)
                        if lst:
                            m["tls"] = {"source": "crt-list", "files": []}
                        else:
                            m["tls"] = {"source": "files", "files": crts}
                continue
            if w == "maxconn" and len(tok) == 2 and tok[1].isdigit():
                g["frontend_maxconn"] = int(tok[1])
                continue
            if w == "stick-table":
                win, size, exp = table_window(s)
                if win:
                    sec_m["http_window"] = win
                if size:
                    sec_m["table_size"] = size
                if exp:
                    sec_m["table_expire"] = exp
                continue
            if w == "tcp-request" and re.match(r"tcp-request connection reject if \{ src -f \S+ \}$", _norm(s)):
                continue
            if re.match(r"http-request set-var\((req|txn)\.host\) req\.hdr\(host\),field\(1,:\)(,lower)?$", _norm(s)):
                continue
            mm = re.match(r'http-response set-header\s+(\S+)\s+"([^"]*)"(.*)$', s)
            if mm:
                hname, val, rest = mm.group(1).lower(), mm.group(2), mm.group(3).strip()
                if hname == "strict-transport-security":
                    m["headers"]["hsts"] = val
                    if rest.startswith("if "):
                        doms = []
                        for e in re.findall(r"\{([^}]*)\}", rest):
                            hs = host_of(e.strip())
                            if hs is None:
                                doms = None
                                break
                            doms += [h.lstrip("*").lstrip(".") for h in hs]
                        if doms is None:
                            unknown(name, s, extra)
                        else:
                            m["headers"]["hsts_domains"] = sorted(set(doms))
                    continue
                if hname == "x-frame-options":
                    m["headers"]["frame_options"] = val
                    continue
                if hname == "x-content-type-options" and not rest:
                    m["headers"]["nosniff"] = True
                    continue
                if hname == "server" and not rest:
                    m["headers"]["server"] = val
                    continue
            if w == "http-request" and len(tok) > 1 and tok[1] in ("silent-drop", "deny", "tarpit", "set-log-level"):
                r = parse_rate(s, acls)
                if r:
                    rules.append(r)
                    continue
            mm = re.match(r"http-request redirect code (\d+) location (\S+) if (.*)$", s)
            if mm:
                cond = mm.group(3).replace("!" + ACME_COND, " ").replace(ACME_COND, " ")
                cond = re.sub(r"!\s*\{ path_beg /\.well-known/acme-challenge/ \}", " ", cond)
                terms = parse_terms(cond, acls)
                rt = split_route(terms) if terms is not None else None
                if rt:
                    redirects.append((int(mm.group(1)), mm.group(2), rt[0], rt[1], kind))
                    continue
            mm = re.match(r"use_backend\s+(\S+)\s+if\s+(.*)$", s)
            if mm:
                be, cond = mm.group(1), mm.group(2)
                if "acme-challenge" in cond and any(_port(x[2]) == ctx["acme_port"] for x in backend_servers(be) if len(x) > 2):
                    m["listen"]["acme_http01"] = True
                    continue
                terms = parse_terms(cond, acls)
                rt = split_route(terms) if terms is not None else None
                if rt and be in backs:
                    routes.setdefault(be, []).append((rt[0], rt[1], kind))
                    continue
            if w == "default_backend" and len(tok) == 2:
                if kind == "http":
                    bbody = backs.get(tok[1], (None, []))[1]
                    m["listen"]["redirect_to_https"] = any("redirect scheme https" in x for x in bbody)
                continue
            unknown(name, s, extra)
        return rules

    def tcp_frontend(name):
        sec, body = fronts[name]
        acls = {}
        extra = m["extra"]["tcp"]
        for s in body:
            tok = s.split()
            w = tok[0]
            n = _norm(s)
            if w == "acl" and len(tok) >= 3:
                acls.setdefault(tok[1], []).append(" ".join(tok[2:]))
                if tok[2] == "src":
                    acls["__trusted__"] = [" ".join(tok[2:])]
                    for v in tok[3:]:
                        if v not in sec_m["trusted"]:
                            sec_m["trusted"].append(v)
                continue
            if n in ("mode tcp", "option tcplog", "tcp-request connection track-sc0 src",
                     "tcp-request content accept if { req_ssl_hello_type 1 }") or w == "tcp-request" and \
                    tok[1:2] == ["inspect-delay"]:
                continue
            if w == "bind":
                m["listen"]["https_bind"] = tok[1]
                continue
            if w == "maxconn":
                continue
            if w == "stick-table":
                win, _, _ = table_window(s)
                if win:
                    sec_m["tcp_window"] = win
                continue
            if re.match(r"tcp-request connection reject if \{ src -f \S+ \}$", n):
                continue
            mm = re.match(r"tcp-request connection reject if (?:!\S+ )?\{ sc0_conn_(rate|cur) gt (\d+) \}$", n)
            if mm:
                sec_m["tcp_conn_" + mm.group(1)] = int(mm.group(2))
                continue
            mm = re.match(r"tcp-request content reject if (.*)$", s)
            if mm:
                terms = parse_terms(mm.group(1), acls)
                ok = terms is not None
                block = {"pattern": None, "except": []}
                for neg, exprs in terms or []:
                    hs = []
                    for e in exprs:
                        h = host_of(e)
                        if h is None:
                            ok = False
                            break
                        hs += h
                    if not ok:
                        break
                    if neg:
                        block["except"] += hs
                    elif block["pattern"] is None and len(hs) == 1:
                        block["pattern"] = hs[0]
                    else:
                        ok = False
                if ok and block["pattern"]:
                    sec_m["sni_block"].append(block)
                    continue
            mm = re.match(r"use_backend\s+(\S+)\s+if\s+(.*)$", s)
            if mm:
                be = mm.group(1)
                tcp_backends.add(be)
                ports = [_port(x[2]) for x in backend_servers(be) if len(x) > 2]
                if m["listen"]["h1_port"] in ports or (fe_h1 and _port(_bind_info(fronts[fe_h1][1]).split()[0]) in ports):
                    terms = parse_terms(mm.group(2), acls)
                    hs = []
                    for neg, exprs in terms or []:
                        h = host_of(exprs[0]) if len(exprs) == 1 and not neg else None
                        if h:
                            hs += h
                    if hs:
                        h1_sni.extend(hs)
                        continue
                if m["listen"]["h2_port"] in ports:
                    continue      # default route to the HTTP/2 frontend
            if w == "default_backend":
                tcp_backends.add(tok[1])
                continue
            unknown(name, s, extra)

    if fe_h2:
        r = http_frontend(fe_h2, "h2")
        sec_m["rules_https"] = [x[0] for x in r]
        if any(x[1] for x in r):
            sec_m["exempt_trusted"] = True
    if fe_h1:
        saved = list(m["extra"]["https"])
        http_frontend(fe_h1, "h1")
        m["extra"]["https"] = saved          # duplicate lines of the second HTTPS frontend
    if fe_http:
        r = http_frontend(fe_http, "http")
        sec_m["rules_http"] = [x[0] for x in r]
    if fe_tcp:
        tcp_frontend(fe_tcp)
    for name, (sec, body) in fronts.items():
        if name not in used_fronts:
            m["raw"].append("\n".join(lines[sec.start:sec.end]).strip("\n"))
            notes.append(f"Frontend {name} kept as raw section.")

    # backends
    defaults_of = set()
    for name, (sec, body) in fronts.items():
        for s in body:
            if s.startswith("default_backend "):
                defaults_of.add(s.split()[1])
    for name, (sec, body) in backs.items():
        mode = next((s.split()[1] for s in body if s.startswith("mode ") and len(s.split()) > 1), "http")
        srv = backend_servers(name)
        if name in tcp_backends or (mode == "tcp" and all(len(x) > 2 and x[2].startswith("127.0.0.1:") for x in srv)
                                    and srv and _port(srv[0][2]) in (m["listen"]["h2_port"], m["listen"]["h1_port"])):
            continue
        if any(len(x) > 2 and _port(x[2]) == ctx["acme_port"] and x[2].startswith("127.0.0.1") for x in srv):
            continue
        if not srv and name in defaults_of and name not in routes:
            continue          # NO-SSL / NO-MATCH style default backends
        if mode != "http":
            m["raw"].append("\n".join(lines[sec.start:sec.end]).strip("\n"))
            notes.append(f"Backend {name} (mode {mode}) kept as raw section.")
            continue
        m["sites"].append(parse_site(name, _lead_comment(sec, lines), body, unmapped))

    # attach routes
    site_map = {s["name"]: s for s in m["sites"]}
    for be, rl in routes.items():
        s = site_map.get(be)
        if not s:
            for host, conds, kind in rl:
                unmapped.append(f"route {host} -> {be}: backend not managed")
            continue
        for host, conds, kind in rl:
            r = {"host": host, "conds": conds}
            if r not in s["routes"]:
                s["routes"].append(r)
            if kind == "http":
                s["http"] = True
            if kind == "h1":
                s["http1"] = True
    for s in m["sites"]:
        if s["http1"]:
            extra_h1 = [r["host"] for r in s["routes"] if not r["conds"] and r["host"] not in h1_sni]
            if extra_h1:
                notes.append(f"Site {s['name']}: {', '.join(extra_h1)} will also be routed to the HTTP/1.1 frontend "
                             "by TLS name (SNI), not only via the HTTP/2 frontend.")
        if not s["routes"]:
            s["enabled"] = False
            notes.append(f"Site {s['name']} has no host rules; imported as disabled.")

    # redirect sites
    by_target = {}
    for code, loc, host, conds, kind in redirects:
        keep = loc.endswith("%[capture.req.uri]")
        target = loc[:-len("%[capture.req.uri]")] if keep else loc
        key = (code, target, keep)
        s = by_target.get(key)
        if not s:
            s = new_site(("REDIRECT-" + re.sub(r"[^A-Za-z0-9]+", "-", host).strip("-")).upper()[:64])
            s.update(type="redirect", target=target, keep_uri=keep, code=code,
                     description=f"Redirect to {target}")
            by_target[key] = s
        r = {"host": host, "conds": conds}
        if r not in s["routes"]:
            s["routes"].append(r)
        if kind == "http":
            s["http"] = True
    m["sites"] += list(by_target.values())

    # other sections
    for sec in secs:
        if sec.kind in ("global", "defaults", "frontend", "backend"):
            continue
        m["raw"].append("\n".join(lines[sec.start:sec.end]).strip("\n"))
        notes.append(f"Section {sec.title} kept as raw section.")

    if not fe_h2:
        m["tls"] = {"source": "crt-list", "files": []}
    if not fe_http and not fronts:
        m = normalize(default_model())
        notes.append("No frontends found: starting with the default setup (port 80 + HTTPS once a certificate exists).")
        return m, {"notes": notes, "unmapped": unmapped}
    return normalize(m), {"notes": notes, "unmapped": unmapped}


def parse_site(name, comment, body, unmapped):
    s = new_site(name)
    s["description"] = comment
    acls = {}
    allow_acl = None
    pending = []
    for line in body:
        tok = line.split()
        n = _norm(line)
        w = tok[0]
        if n == "mode http":
            continue
        if w == "balance" and len(tok) == 2:
            s["balance"] = tok[1]
        elif n == "option http-keep-alive":
            s["keepalive"] = True
        elif n == "option prefer-last-server":
            s["prefer_last"] = True
        elif n == "option srvtcpka":
            s["srvtcpka"] = True
        elif w == "cookie" and len(tok) == 4 and tok[2:] == ["insert", "nocache"]:
            s["cookie"] = tok[1]
        elif w == "timeout" and len(tok) == 3 and tok[1] in ("server", "tunnel"):
            s["timeout_" + tok[1]] = tok[2]
        elif w == "acl" and len(tok) >= 4:
            acls.setdefault(tok[1], []).append(tok[2:])
        elif w == "server" and len(tok) >= 3:
            v = {"name": tok[1], "address": tok[2], "tls": False, "verify": False, "check": False, "options": ""}
            opts, i = [], 3
            while i < len(tok):
                t = tok[i]
                if t == "ssl":
                    v["tls"] = True
                elif t == "verify" and i + 1 < len(tok):
                    v["verify"] = tok[i + 1] == "required"
                    i += 1
                elif t == "ca-file" and i + 1 < len(tok) and tok[i + 1] == "@system-ca":
                    i += 1
                elif t == "check":
                    v["check"] = True
                else:
                    opts.append(t)
                i += 1
            if s["cookie"] is not None and opts[-2:] == ["cookie", tok[1]]:
                opts = opts[:-2]
            v["options"] = " ".join(opts)
            s["servers"].append(v)
        elif re.match(r"http-request deny deny_status 403 unless (\S+)$", n):
            allow_acl = n.split()[-1]
        elif n == "http-request deny deny_status 403":
            s["block"] = True
        elif re.match(r"http-request deny deny_status 403 if !\{ src [^}]+ \}$", n):
            s["allow_src"] = n.split("{ src ")[1].rstrip(" }").split()
        else:
            mm = re.match(r"http-request redirect code (\d+) location (\S+) if \{ path -i (?:-m beg )?(\S+) \}$", n)
            if mm:
                s["redirects"].append({"path": mm.group(3), "match": "prefix" if "-m beg" in n else "exact",
                                       "to": mm.group(2), "code": int(mm.group(1))})
            else:
                pending.append(line)
    if allow_acl and allow_acl in acls:
        paths = []
        for spec in acls.pop(allow_acl):
            fetch, method, vals, has_file = _flags(spec)
            if fetch == "path_beg" or (fetch == "path" and method == "beg"):
                paths += vals
            elif fetch == "path" and method in (None, "str"):
                paths += ["=" + v for v in vals]
            else:
                pending.append("acl " + allow_acl + " " + " ".join(spec))
        s["allow_paths"] = [] if "/" in paths else paths
    elif allow_acl:
        pending.append(f"http-request deny deny_status 403 unless {allow_acl}")
    for k, specs in acls.items():
        for spec in specs:
            pending.insert(0, f"acl {k} {' '.join(spec)}")
    if s["block"] and not s["servers"]:
        s["block"] = False
    s["cookie"] = s["cookie"] or ""
    s["extra"] = pending
    for p in pending:
        unmapped.append(f"backend {name}: {p}")
    return s
