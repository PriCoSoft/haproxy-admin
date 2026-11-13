"""Append-only audit log (JSON lines)."""
import datetime
import json
import threading

from flask import current_app, g, has_request_context, request

_lock = threading.Lock()


def audit(action, detail="", user=None):
    s = current_app.extensions["hpa_settings"]
    u = user or (getattr(g, "user", None) if has_request_context() else None) or {}
    entry = {
        "time": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "user": u.get("upn", "-"),
        "ip": request.remote_addr if has_request_context() else "-",
        "action": action,
        "detail": detail,
    }
    line = json.dumps(entry, ensure_ascii=False)
    with _lock:
        try:
            with open(s.audit_log, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except OSError as e:
            current_app.logger.error("audit log write failed: %s (%s)", e, line)
    current_app.logger.info("AUDIT %s", line)


def read_audit(limit=300):
    s = current_app.extensions["hpa_settings"]
    try:
        with open(s.audit_log, encoding="utf-8") as f:
            lines = f.readlines()[-limit:]
    except OSError:
        return []
    out = []
    for ln in reversed(lines):
        try:
            out.append(json.loads(ln))
        except ValueError:
            continue
    return out
