"""Log viewer: HAProxy traffic log (rsyslog file) and the haproxy service journal."""
import re

from flask import render_template, request

from .auth import login_required
from .helper import HelperError
from .views import H, actor, bp

HTTP_RE = re.compile(
    r"^(?P<time>\w{3} +\d+ [\d:]+|\d{4}-\d\d-\d\dT[\d:.]+\S*) \S+ haproxy\[\d+\]: (?P<client>\S+?):\d+ \[[^\]]+\] "
    r"(?P<fe>\S+?)~? (?P<be>[^/\s]+)/(?P<srv>\S+) (?P<timers>\S+) (?P<status>-?\d+) (?P<bytes>\d+) \S+ \S+ "
    r"(?P<term>\S+) (?P<conns>\S+) \S+(?: \{(?P<host>[^}]*)\})? \"(?P<req>[^\"]*)\"")
TCP_RE = re.compile(
    r"^(?P<time>\w{3} +\d+ [\d:]+|\d{4}-\d\d-\d\dT[\d:.]+\S*) \S+ haproxy\[\d+\]: (?P<client>\S+?):\d+ \[[^\]]+\] "
    r"(?P<fe>\S+) (?P<be>[^/\s]+)/(?P<srv>\S+) (?P<timers>\S+) (?P<bytes>\d+) (?P<term>\S+)")
TERM_HINTS = {"C": "client aborted", "S": "server aborted / refused", "P": "proxy (deny, silent-drop, error)",
              "R": "resource limit", "I": "internal error", "D": "server down", "c": "client timeout",
              "s": "server timeout"}


def parse(line):
    m = HTTP_RE.match(line)
    if m:
        d = m.groupdict()
        d["kind"] = "http"
        st = int(d["status"])
        d["cls"] = "bad" if st >= 500 or st < 0 else "warn" if st >= 400 else "good" if st < 300 else ""
        method, _, rest = d["req"].partition(" ")
        url = rest.rsplit(" ", 1)[0] if " " in rest else rest
        url = re.sub(r"^https?://[^/]+", "", url)
        d["method"], d["path"] = method, url
        d["total"] = d["timers"].split("/")[-1]
        d["term_hint"] = TERM_HINTS.get(d["term"][:1], "")
        return d
    m = TCP_RE.match(line)
    if m:
        d = m.groupdict()
        d["kind"] = "tcp"
        d["total"] = d["timers"].split("/")[-1]
        d["term_hint"] = TERM_HINTS.get(d["term"][:1], "")
        return d
    return {"kind": "raw", "raw": line}


@bp.route("/logs")
@login_required
def logs():
    source = request.args.get("source", "traffic")
    source = source if source in ("traffic", "service") else "traffic"
    q = request.args.get("q", "").strip()[:200]
    try:
        lines = max(50, min(int(request.args.get("lines", "300")), 5000))
    except ValueError:
        lines = 300
    show_tcp = bool(request.args.get("tcp"))
    status = request.args.get("status", "")
    args = ["logs", "--source", source, "--lines", str(lines)]
    if q:
        args += ["--grep", q]
    if source == "traffic" and not show_tcp:
        args += ["--exclude", "fTCP-443 "]
    if status in ("4", "5"):
        args += ["--status", status]
    error, rows = None, []
    try:
        rc, out, err = H().run(args, actor=actor(), timeout=30)
        if rc != 0:
            error = (err or out).strip() or f"helper failed (rc {rc})"
        text = out
    except (HelperError, OSError) as e:
        error, text = str(e), ""
    raw = [l for l in text.split("\n") if l.strip()]
    if source == "traffic":
        rows = [parse(l) for l in reversed(raw)]
    else:
        rows = [{"kind": "raw", "raw": l} for l in reversed(raw)]
    return render_template("logs.html", rows=rows, source=source, q=q, lines=lines, show_tcp=show_tcp,
                           status=status, error=error, auto=bool(request.args.get("auto")))
