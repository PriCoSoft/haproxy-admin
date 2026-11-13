"""Background jobs (certbot runs) with live log output. Single gunicorn worker -> in-memory store."""
import secrets
import threading
import time

_jobs = {}
_lock = threading.Lock()
MAX_JOBS = 50


class Job:
    def __init__(self, title, user):
        self.id = secrets.token_urlsafe(8)
        self.title = title
        self.user = user
        self.lines = []
        self.rc = None
        self.started = time.time()
        self.finished = None

    @property
    def running(self):
        return self.rc is None

    def as_dict(self, since=0):
        return {"id": self.id, "title": self.title, "user": self.user, "rc": self.rc,
                "running": self.running, "lines": self.lines[since:], "total": len(self.lines),
                "started": self.started, "finished": self.finished}


def start(title, user, popen_factory, on_done=None):
    job = Job(title, user)
    with _lock:
        _jobs[job.id] = job
        if len(_jobs) > MAX_JOBS:
            for jid in sorted(_jobs, key=lambda k: _jobs[k].started)[:len(_jobs) - MAX_JOBS]:
                if not _jobs[jid].running:
                    del _jobs[jid]

    def run():
        try:
            proc = popen_factory()
            for line in proc.stdout:
                job.lines.append(line.rstrip("\n"))
            job.rc = proc.wait()
        except Exception as e:  # noqa: BLE001
            job.lines.append(f"ERROR: {e}")
            job.rc = -1
        job.finished = time.time()
        if on_done:
            try:
                on_done(job)
            except Exception:  # noqa: BLE001
                pass

    threading.Thread(target=run, daemon=True).start()
    return job


def get(job_id):
    with _lock:
        return _jobs.get(job_id)


def recent():
    with _lock:
        return sorted(_jobs.values(), key=lambda j: j.started, reverse=True)
