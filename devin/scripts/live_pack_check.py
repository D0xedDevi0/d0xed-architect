"""Live end-to-end check of the packager on the VPS.

Run with:  DEVIN_LIVE_PW=<passphrase> venv/bin/python live_pack_check.py
The passphrase is read from the environment and never printed; the script
prints only counts, names, and hashes.
"""
import os
import shutil
import sys
import tempfile

sys.path.insert(0, "/srv/looper-agents/devin/app")

from devin import transport
from devin.crypto import IntegrityError, is_bundle
from devin.pack import pack_github, render_pack, verify_pack, open_pack

PW = os.environ["DEVIN_LIVE_PW"]
REPO = "https://github.com/pallets/itsdangerous"

res = pack_github(REPO, transport.github_fetch, PW)
print("files:", res.files)
print("languages:", sorted(res.languages))
print("findings:", res.findings, "blocking:", len(res.blocking))
print("bundle sha256:", res.bundle_sha256[:32])
print("filename:", res.filename())
print("is_bundle:", is_bundle(res.blob), "bytes:", len(res.blob))
print("source sha256:", res.source_sha256[:32])

# plaintext must not survive sealing
leak = any(tok in res.blob for tok in (b"import ", b"def ", b"class "))
print("plaintext leaked into bundle:", leak)

info = verify_pack(res.blob, PW)
print("verify checked:", info["checked"], "members:", len(info["members"]))

dest = tempfile.mkdtemp(prefix="live-open-")
try:
    manifest = open_pack(res.blob, PW, dest)
    found = []
    for root, _dirs, files in os.walk(dest):
        for f in files:
            p = os.path.join(root, f)
            found.append(os.path.relpath(p, dest))
    print("extracted files:", len(found))
    print("has signer module:", any("signer.py" in f for f in found))
    print("manifest files:", manifest["file_count"])
finally:
    shutil.rmtree(dest, ignore_errors=True)

try:
    open_pack(res.blob, "definitely not the passphrase", tempfile.mkdtemp())
    print("WRONG-PASSPHRASE GUARD: FAILED (it opened!)")
except IntegrityError:
    print("wrong passphrase -> IntegrityError: True")

receipt = render_pack(res, max_len=1000)
print("receipt has passphrase:", PW in receipt)
print("receipt chars:", len(receipt))
print("receipt mentions chacha20:", "chacha20" in receipt)