"""Round-trip test: import a config, generate, validate, re-import, regenerate (must be identical).

Usage (on the proxy, read-only):  python3 tests/roundtrip.py /etc/haproxy/haproxy.cfg /tmp/out-dir
"""
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from haproxy_admin import importer, model  # noqa: E402

src, outdir = sys.argv[1], sys.argv[2]
os.makedirs(outdir, exist_ok=True)
deny = os.path.join(outdir, "denylist.acl")
open(deny, "a").close()
ctx = {"crt_list": "/etc/haproxy/crt-list.txt", "crt_list_count": 1, "acme_port": 8402, "denylist": deny}
text = open(src, encoding="utf-8").read()
m, rep = importer.import_config(text, ctx)
print("NOTES:", *rep["notes"], sep="\n  ")
print("UNMAPPED:", *rep["unmapped"], sep="\n  ")
errs = model.validate(m)
print("VALIDATE:", errs or "ok")
gen = model.render(m, ctx)
open(os.path.join(outdir, "generated.cfg"), "w").write(gen)
open(os.path.join(outdir, "model.json"), "w").write(json.dumps(m, indent=1))
p = subprocess.run(["haproxy", "-c", "-f", os.path.join(outdir, "generated.cfg")], capture_output=True, text=True)
print("HAPROXY -c:", p.returncode, (p.stdout + p.stderr).strip()[-2000:])
m2, body = model.extract(gen)
assert m2 == m, "embedded model differs"
m3, rep3 = importer.import_config(body, ctx)
gen3 = model.render_body(m3, ctx)
print("REIMPORT unmapped:", rep3["unmapped"])
print("ROUNDTRIP body identical:", gen3 == body)
if gen3 != body:
    import difflib
    print("\n".join(difflib.unified_diff(body.split("\n"), gen3.split("\n"), lineterm="")))
if m3 != m:
    for k in m:
        if m[k] != m3[k]:
            print("MODEL DIFF in", k)
