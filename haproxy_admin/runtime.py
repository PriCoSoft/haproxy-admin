"""Read-only access to the HAProxy runtime API (admin socket)."""
import csv
import datetime
import io
import socket


class Runtime:
    def __init__(self, path, timeout=5.0):
        self.path = path
        self.timeout = timeout

    def cmd(self, command):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(self.timeout)
            s.connect(self.path)
            s.sendall(command.encode() + b"\n")
            chunks = []
            while True:
                b = s.recv(65536)
                if not b:
                    break
                chunks.append(b)
        return b"".join(chunks).decode("utf-8", "replace")

    @staticmethod
    def _kv(text):
        out = {}
        for line in text.splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                out[k.strip()] = v.strip()
        return out

    def info(self):
        return self._kv(self.cmd("show info"))

    def stats(self):
        text = self.cmd("show stat")
        if text.startswith("# "):
            text = text[2:]
        return [row for row in csv.DictReader(io.StringIO(text)) if row.get("pxname")]

    def ssl_cert_paths(self):
        text = self.cmd("show ssl cert")
        return [ln.strip().lstrip("*") for ln in text.splitlines() if ln.strip() and not ln.startswith("#")]

    def ssl_cert_detail(self, path):
        d = self._kv(self.cmd(f"show ssl cert {path}"))
        sans = [x.strip()[4:] for x in d.get("Subject Alternative Name", "").split(",") if x.strip().startswith("DNS:")]
        not_after = parse_openssl_date(d.get("notAfter", ""))
        return {
            "path": path,
            "subject": d.get("Subject", ""),
            "issuer": d.get("Issuer", ""),
            "sans": sans,
            "not_after": not_after,
            "days_left": days_left(not_after),
        }

    def ssl_certs(self):
        out = []
        for p in self.ssl_cert_paths():
            try:
                out.append(self.ssl_cert_detail(p))
            except OSError:
                out.append({"path": p, "sans": [], "not_after": None, "days_left": None, "subject": "", "issuer": ""})
        return out


    def table(self, name):
        return parse_table(self.cmd(f"show table {name}"))


def parse_openssl_date(value):
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y GMT"):
        try:
            return datetime.datetime.strptime(value, fmt).replace(tzinfo=datetime.timezone.utc)
        except ValueError:
            continue
    return None


def days_left(dt):
    if not dt:
        return None
    return int((dt - datetime.datetime.now(datetime.timezone.utc)).total_seconds() // 86400)


def host_covered(host, sans):
    host = host.lower().lstrip("*.") if host.startswith("*.") else host.lower()
    for san in sans:
        san = san.lower()
        if san == host:
            return True
        if san.startswith("*.") and "." in host and host.split(".", 1)[1] == san[2:]:
            return True
    return False


def _table_value(v):
    try:
        return int(v)
    except ValueError:
        return v


def parse_table(text):
    """Parse 'show table <name>' output into dicts (key, conn_rate, http_err_rate, ...)."""
    rows = []
    for line in text.splitlines():
        if not line.startswith("0x") or ": " not in line:
            continue
        entry = {}
        for part in line.split(": ", 1)[1].split():
            if "=" in part:
                k, v = part.split("=", 1)
                entry[k.split("(")[0]] = _table_value(v)
        if "key" in entry:
            entry["key"] = str(entry["key"])
            rows.append(entry)
    return rows
