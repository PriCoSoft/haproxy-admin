"""Light-weight haproxy.cfg parser: sections, host routing, backends and generators.

The parser never rewrites the file as a whole. Changes are made by inserting or
replacing whole lines, so formatting and comments of hand-written config survive.
"""
import re
from dataclasses import dataclass, field

SECTION_KEYWORDS = {
    "global", "defaults", "frontend", "backend", "listen", "userlist", "peers",
    "resolvers", "mailers", "program", "http-errors", "ring", "cache",
}

HOST_RE = re.compile(r"var\((?:req|txn)\.host\)\s+(?:-m\s+str\s+)?-i\s+(?:-m\s+(\w+)\s+)?(\S+)"
                     r"|var\((?:req|txn)\.host\)\s+-m\s+(\w+)\s+-i\s+(\S+)")
SNI_RE = re.compile(r"req(?:_ssl|\.ssl)_sni\s+-i\s+(?:-m\s+(\w+)\s+)?(\S+)")
BLOCK_RE = re.compile(r"\{[^}]*\}")

HOSTNAME_RE = re.compile(r"^(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
BACKEND_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
SERVER_RE = re.compile(r"^([A-Za-z0-9_.-]{1,64})\s+([A-Za-z0-9_.\-]+|\[[0-9a-fA-F:]+\]):(\d{1,5})$")
PATH_RE = re.compile(r"^/[^\s\"'#]*$")


@dataclass
class Section:
    kind: str
    name: str
    header: int          # index of the header line
    start: int           # first line incl. leading comment block
    end: int             # exclusive
    lines: list = field(default_factory=list)

    @property
    def title(self):
        return f"{self.kind} {self.name}".strip()

    @property
    def text(self):
        return "\n".join(self.lines)


def split_lines(text):
    return text.split("\n")


def parse_sections(text):
    lines = split_lines(text)
    headers = []
    for i, line in enumerate(lines):
        if not line or line[0] in " \t#":
            continue
        tok = line.split()
        if tok and tok[0] in SECTION_KEYWORDS:
            headers.append((i, tok[0], " ".join(tok[1:2])))

    sections = []
    for n, (h, kind, name) in enumerate(headers):
        # leading contiguous comment lines directly above the header belong to this section
        start = h
        while start - 1 >= 0 and lines[start - 1].strip().startswith("#") and (
                not sections or start - 1 >= sections[-1].header + 1):
            start -= 1
        end = headers[n + 1][0] if n + 1 < len(headers) else len(lines)
        sections.append(Section(kind, name, h, start, end))

    # fix ends so the next section's leading comments are not counted twice
    for n in range(len(sections) - 1):
        sections[n].end = sections[n + 1].start
    if sections and sections[-1].end > len(lines):
        sections[-1].end = len(lines)
    for s in sections:
        s.lines = lines[s.start:s.end]
    return sections


def _directives(sec, all_lines):
    for i in range(sec.header + 1, sec.end):
        s = all_lines[i].strip()
        if s and not s.startswith("#"):
            yield i, s


def _host_tokens(cond):
    hosts, extras = [], []
    rest = cond
    for block in BLOCK_RE.findall(cond):
        rest = rest.replace(block, " ")
        inner = block[1:-1].strip()
        m = HOST_RE.search(inner)
        s = SNI_RE.search(inner)
        if m:
            match = m.group(1) or m.group(3) or "str"
            host = m.group(2) or m.group(4)
            hosts.append(_fmt_host(match, host))
        elif s:
            hosts.append(_fmt_host(s.group(1) or "str", s.group(2)))
        else:
            extras.append(inner)
    for word in rest.split():
        if word not in ("||", "or"):
            extras.append(word)
    return hosts, extras


def _fmt_host(match, host):
    if match == "beg":
        return host + "*"
    if match == "end":
        return "*" + host
    return host


def frontends(text):
    lines = split_lines(text)
    result = []
    for sec in parse_sections(text):
        if sec.kind not in ("frontend", "listen"):
            continue
        fe = {"name": sec.name, "kind": sec.kind, "mode": "tcp" if sec.kind == "listen" else "http",
              "binds": [], "routes": [], "default": None, "has_req_host": False,
              "default_line": None, "first_route_line": None}
        for i, s in _directives(sec, lines):
            tok = s.split()
            if tok[0] == "mode" and len(tok) > 1:
                fe["mode"] = tok[1]
            elif tok[0] == "bind":
                fe["binds"].append(s[4:].strip())
            elif "set-var(req.host)" in s or "set-var(txn.host)" in s:
                fe["has_req_host"] = True
            elif tok[0] == "default_backend" and len(tok) > 1:
                fe["default"] = tok[1]
                fe["default_line"] = i
            elif tok[0] == "use_backend" and len(tok) > 1:
                m = re.match(r"use_backend\s+(\S+)(?:\s+(if|unless)\s+(.*))?$", s)
                if not m:
                    continue
                if fe["first_route_line"] is None:
                    fe["first_route_line"] = i
                hosts, extras = _host_tokens(m.group(3) or "")
                if m.group(2) == "unless":
                    extras.insert(0, "unless")
                fe["routes"].append({"backend": m.group(1), "hosts": hosts, "extras": extras,
                                     "cond": (m.group(3) or "").strip(), "line": i + 1})
        fe["tls"] = any(" ssl " in f" {b} " for b in fe["binds"])
        fe["port80"] = any(re.search(r":80(\s|$)", b) for b in fe["binds"])
        result.append(fe)
    return result


def backends(text):
    lines = split_lines(text)
    result = {}
    for sec in parse_sections(text):
        if sec.kind not in ("backend", "listen"):
            continue
        comment = " ".join(l.strip().lstrip("#").strip() for l in lines[sec.start:sec.header]
                           if l.strip().lstrip("#").strip())
        be = {"name": sec.name, "comment": comment, "mode": "", "servers": [], "line": sec.header + 1}
        for _, s in _directives(sec, lines):
            tok = s.split()
            if tok[0] == "mode" and len(tok) > 1:
                be["mode"] = tok[1]
            elif tok[0] == "server" and len(tok) >= 3:
                be["servers"].append({"name": tok[1], "addr": tok[2], "opts": " ".join(tok[3:])})
        result[sec.name] = be
    return result


def sites(text):
    """Flatten routing into rows: host -> frontend -> backend -> servers."""
    bes = backends(text)
    rows = []
    for fe in frontends(text):
        for r in fe["routes"]:
            for host in [" & ".join(r["hosts"])] if r["hosts"] else ["(no host condition)"]:
                rows.append({"host": host, "frontend": fe["name"], "mode": fe["mode"],
                             "backend": r["backend"], "extras": r["extras"], "line": r["line"],
                             "servers": bes.get(r["backend"], {}).get("servers", []),
                             "comment": bes.get(r["backend"], {}).get("comment", "")})
    rows.sort(key=lambda x: (x["host"].lstrip("*").split(".")[::-1], x["frontend"]))
    return rows


# --------------------------------------------------------------------------- generators

def suggest_backend_name(host):
    labels = host.lstrip("*.").split(".")
    name = "-".join(reversed(labels)).upper()
    if host.startswith("*."):
        name = "WILDCARD-" + name
    return re.sub(r"[^A-Z0-9_.-]", "-", name)[:64]


def host_condition(host):
    if host.startswith("*."):
        return "{ var(req.host) -m end -i ." + host[2:] + " }"
    return "{ var(req.host) -m str -i " + host + " }"


ACME_BACKEND = "ACME-HTTP01"


def add_acme_route(text, port):
    """Route /.well-known/acme-challenge/ on the port-80 frontend(s) to certbot standalone."""
    if "acme-challenge" in text:
        raise ValueError(["An ACME challenge route already exists."])
    lines = split_lines(text)
    targets = [f for f in frontends(text) if f["port80"] and f["mode"] == "http"]
    if not targets:
        raise ValueError(["No HTTP frontend bound to port 80 found."])
    rule = ["\t# ACME HTTP-01 challenges (haproxy-admin / certbot standalone)",
            f"\tuse_backend {ACME_BACKEND} if {{ path_beg /.well-known/acme-challenge/ }}"]
    positions = []
    for fe in targets:
        idx = fe["first_route_line"] if fe["first_route_line"] is not None else fe["default_line"]
        if idx is None:
            raise ValueError([f"Frontend {fe['name']} has no use_backend/default_backend line."])
        while idx - 1 >= 0 and lines[idx - 1].strip().startswith("#") and not lines[idx - 1].strip().startswith("##"):
            idx -= 1
        positions.append(idx)
    for idx in sorted(positions, reverse=True):
        lines[idx:idx] = rule
    while lines and lines[-1].strip() == "":
        lines.pop()
    lines += ["", "## ACME HTTP-01 -> certbot standalone (only listening while a challenge runs)",
              f"backend {ACME_BACKEND}", "\tmode http", f"\tserver certbot 127.0.0.1:{port}", ""]
    return "\n".join(lines)


def replace_section(text, index, new_text):
    secs = parse_sections(text)
    if index < 0 or index >= len(secs):
        raise ValueError(["Unknown section."])
    lines = split_lines(text)
    sec = secs[index]
    new_lines = new_text.split("\n")
    while new_lines and new_lines[-1].strip() == "":
        new_lines.pop()
    # keep the original separator lines (blank lines / final newline) after the section
    trailing = []
    for l in reversed(sec.lines):
        if l.strip():
            break
        trailing.insert(0, l)
    new_lines += trailing or [""]
    lines[sec.start:sec.end] = new_lines
    return "\n".join(lines)
