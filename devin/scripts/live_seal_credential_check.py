"""Prove the PROVISIONED sealing credential works end-to-end.

Runs under systemd with LoadCredentialEncrypted, so the passphrase arrives the
same way the live bot receives it. Only lengths, counts and hashes are printed:
the passphrase value itself never appears in output, logs, or receipts.

Run on the VPS:
  systemd-run --pipe --wait --collect \
    --setenv=PYTHONPATH=/srv/looper-agents/devin/app \
    --property=LoadCredentialEncrypted=bundle_passphrase:/etc/credstore.encrypted/looper-devin.bundle \
    /srv/looper-agents/devin/venv/bin/python /tmp/live_seal_credential_check.py
"""
import os
import shutil
import sys
import tempfile

sys.path.insert(0, "/srv/looper-agents/devin/app")

from devin import transport
from devin.config import resolve_bundle_passphrase
from devin.crypto import IntegrityError, is_bundle
from devin.pack import open_pack, pack_github, render_pack, verify_pack

pw = resolve_bundle_passphrase()
print("credential mounted:", bool(pw), "| passphrase length:", len(pw or ""))
if not pw:
    raise SystemExit("FAIL: no sealing credential reached the process")

res = pack_github("https://github.com/pallets/itsdangerous",
                  transport.github_fetch, pw)
print("sealed: files=%d bytes=%d is_bundle=%s"
      % (res.files, len(res.blob), is_bundle(res.blob)))
print("bundle sha256:", res.bundle_sha256[:24])
print("source sha256:", res.source_sha256[:24])
print("plaintext survived sealing:", any(
    tok in res.blob for tok in (b"def ", b"import ", b"class ")))
print("blocking secret findings:", len(res.blocking))
print("verify checked:", verify_pack(res.blob, pw)["checked"])

dest = tempfile.mkdtemp(prefix="devin-cred-open-")
try:
    manifest = open_pack(res.blob, pw, dest)
    print("opened WITH the provisioned passphrase: file_count =",
          manifest["file_count"])
    print("signer module recovered:",
          os.path.exists(os.path.join(dest, "src", "itsdangerous", "signer.py")))
finally:
    shutil.rmtree(dest, ignore_errors=True)

try:
    open_pack(res.blob, "definitely-not-the-passphrase", tempfile.mkdtemp())
    print("WRONG-PASSPHRASE GUARD FAILED")
except IntegrityError:
    print("wrong passphrase refused: True")

receipt = render_pack(res, max_len=1000)
print("receipt leaks the passphrase:", pw in receipt)
print("receipt chars:", len(receipt))
