"""Send ONE real sealed bundle to the owner's DM, through the bot's own path.

Exercises, live: the provisioned GitHub credential on a PRIVATE repo, the
provisioned sealing key, the packager, and the real Telegram multipart upload.
Only counts, hashes and API results are printed — never a credential or the
passphrase.

Run on the VPS:
  systemd-run --pipe --wait --collect \
    --setenv=PYTHONPATH=/srv/looper-agents/devin/app \
    --property=LoadCredentialEncrypted=telegram_token:/etc/credstore.encrypted/looper-devin.token \
    --property=LoadCredentialEncrypted=bundle_passphrase:/etc/credstore.encrypted/looper-devin.bundle \
    --property=LoadCredentialEncrypted=github_token:/etc/credstore.encrypted/looper-devin.github \
    /srv/looper-agents/devin/venv/bin/python /tmp/live_dm_bundle.py <owner_user_id>
"""
import os
import sys

sys.path.insert(0, "/srv/looper-agents/devin/app")

from devin import transport
from devin.bot import DevinBot
from devin.config import (Config, Limits, resolve_bundle_passphrase,
                          resolve_github_token)
from devin.crypto import IntegrityError, is_bundle
from devin.pack import open_pack, pack_github, render_pack, verify_pack

OWNER = int(sys.argv[1])
REPO = "https://github.com/D0xedDevi0/hermes-ingest"

creds = os.environ.get("CREDENTIALS_DIRECTORY", "")
with open(os.path.join(creds, "telegram_token"), "rb") as fh:
    tg_token = fh.read().decode().strip()

pw = resolve_bundle_passphrase()
gtok = resolve_github_token()
print("credentials mounted -> sealing key: %s | github token: %s"
      % (bool(pw), bool(gtok)))
if not pw or not gtok:
    raise SystemExit("FAIL: a required credential did not reach the process")

res = pack_github(REPO, transport.github_fetch, pw,
                  label="hermes-ingest", token=gtok)
print("sealed PRIVATE repo: files=%d bytes=%d is_bundle=%s"
      % (res.files, len(res.blob), is_bundle(res.blob)))
print("bundle sha256:", res.bundle_sha256[:24])
print("source sha256:", res.source_sha256[:24])
print("blocking secret findings:", len(res.blocking))
print("plaintext survived sealing:", any(
    tok in res.blob for tok in (b"def ", b"import ", b"class ")))
print("verify checked:", verify_pack(res.blob, pw)["checked"])
print("filename:", res.filename())

cfg = Config(token=tg_token, allowed_user_ids=(OWNER,),
             allowed_group_ids=(-1004351143165,), limits=Limits(),
             bot_id=None, bot_username="DEVinlooperbot")
bot = DevinBot(cfg, transport.telegram_call, transport.github_fetch,
               transport.public_fetch, bundle_passphrase=pw,
               file_get=transport.telegram_file_get)

caption = render_pack(res, max_len=1000)
print("caption leaks passphrase:", pw in caption, "| bytes:", len(res.blob))
bot._send_document(OWNER, res.filename(), res.blob, caption=caption,
                   boundary="----devin" + res.bundle_sha256[:16])
print("sendDocument returned without raising -> delivered to DM", OWNER)
print("the file is encrypted; only the passphrase you set opens it")
try:
    open_pack(res.blob, "wrong-passphrase", "/tmp/devin-should-not-exist")
except IntegrityError:
    print("wrong passphrase refused: True")
