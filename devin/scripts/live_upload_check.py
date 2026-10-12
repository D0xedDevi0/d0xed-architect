"""Live check of the UPLOAD intake path on the VPS.

Builds a real ZIP in memory (including a traversal member and a symlink member),
runs it through exactly the code the bot runs — sniff, intake, deep_tree_report,
build_pack — and prints only counts, names, and hashes.

Run:  DEVIN_LIVE_PW=<passphrase> venv/bin/python live_upload_check.py
The passphrase is read from the environment and never printed.
"""
import io
import os
import shutil
import sys
import tempfile
import zipfile

sys.path.insert(0, "/srv/looper-agents/devin/app")

from devin import transport  # noqa: F401  (proves the module imports cleanly)
from devin.analysis import AnalysisLimits
from devin.crypto import is_bundle
from devin.deep_audit import deep_tree_report
from devin.pack import build_pack, render_pack, verify_pack
from devin.upload import cleanup, intake, sniff

PW = os.environ["DEVIN_LIVE_PW"]
APP = "/srv/looper-agents/devin/app"


def build_zip():
    """Zip the real DEVin app tree + two hostile members."""
    buf = io.BytesIO()
    count = 0
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for dirpath, dirnames, filenames in os.walk(os.path.join(APP, "devin")):
            dirnames[:] = [d for d in dirnames if d != "__pycache__"]
            for fn in filenames:
                if not fn.endswith(".py"):
                    continue
                full = os.path.join(dirpath, fn)
                rel = os.path.relpath(full, APP).replace(os.sep, "/")
                with open(full, "rb") as fh:
                    z.writestr(rel, fh.read())
                count += 1
        z.writestr("../escape.txt", b"this must never be written")
        info = zipfile.ZipInfo("symlinked")
        info.external_attr = (0o120777 << 16)
        z.writestr(info, "/etc/passwd")
    return buf.getvalue(), count


data, wrote = build_zip()
print("zip built from real tree: %d files, %d bytes" % (wrote, len(data)))
print("magic bytes accepted:", sniff("zip", data))

root, truncated = intake("zip", data, AnalysisLimits())
print("extracted, truncated:", truncated)
try:
    found = []
    for dirpath, _d, files in os.walk(root):
        for f in files:
            found.append(os.path.relpath(os.path.join(dirpath, f), root))
    print("files on disk:", len(found))
    print("own layout preserved (devin/bot.py):",
          "devin/bot.py" in [f.replace(os.sep, "/") for f in found])
    print("traversal member escaped:", os.path.exists(
        os.path.join(os.path.dirname(root), "escape.txt")))
    print("symlink member materialized:", any(
        os.path.islink(os.path.join(dirpath, f))
        for dirpath, _d, files in os.walk(root) for f in files))

    report = deep_tree_report(root, owner="upload", repo="devin-app.zip")
    print("report: files=%d loc=%d languages=%d findings=%d"
          % (report.files_scanned, report.loc, len(report.languages),
             len(report.findings)))
    print("languages:", sorted(report.languages)[:8])

    res = build_pack(root, PW, label="devin-app")
    print("sealed: files=%d bytes=%d is_bundle=%s"
          % (res.files, len(res.blob), is_bundle(res.blob)))
    print("plaintext in bundle:", any(
        tok in res.blob for tok in (b"def ", b"import ", b"class ")))
    info = verify_pack(res.blob, PW)
    print("verify checked:", info["checked"])
    print("receipt has passphrase:", PW in render_pack(res, max_len=800))
finally:
    cleanup(root)
    print("temp tree cleaned:", not os.path.exists(root))