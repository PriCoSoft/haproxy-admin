"""Client for the privileged helper (invoked via sudo with fixed sub-commands)."""
import json
import subprocess


class HelperError(Exception):
    pass


class Helper:
    def __init__(self, path):
        self.path = path

    def _cmd(self, args, actor=None):
        cmd = ["sudo", "-n", self.path]
        if actor:
            cmd += ["--actor", actor]
        return cmd + list(args)

    def run(self, args, stdin=None, actor=None, timeout=180):
        """Run helper; returns (returncode, stdout, stderr) as text."""
        p = subprocess.run(
            self._cmd(args, actor),
            input=stdin.encode("utf-8") if isinstance(stdin, str) else stdin,
            capture_output=True,
            timeout=timeout,
        )
        return p.returncode, p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace")

    def json(self, args, stdin=None, actor=None, timeout=60):
        rc, out, err = self.run(args, stdin=stdin, actor=actor, timeout=timeout)
        try:
            data = json.loads(out) if out.strip() else None
        except ValueError:
            data = None
        if data is None:
            raise HelperError((err or out or f"helper exited with {rc}").strip())
        return rc, data

    def popen(self, args, actor=None):
        return subprocess.Popen(
            self._cmd(args, actor),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )
