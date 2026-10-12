# DEVin deployment (Looper #706 / ERC-8004 agent 87226)

Read-only, bounded Telegram bot. **Stdlib only** — no third-party runtime
dependencies, so the target only needs `python3`. The bot is isolated exactly
like the other Looper companions on the VPS (`looper-glass`, `looper-mrbates`):

- its own unprivileged user `looper-devin`,
- its own tree under `/srv/looper-agents/devin/`,
- the token as an **encrypted systemd credential** (`LoadCredentialEncrypted`),
  never in `Environment=` or on disk in cleartext,
- a hardened unit (`ProtectSystem=strict`, `NoNewPrivileges`, empty
  `CapabilityBoundingSet`, restricted address families, memory/task caps).

## Preconditions (all must hold)

1. The token belongs to the pinned identity — startup calls `getMe` and refuses
   any bot other than `DEVIN_BOT_ID` / `DEVIN_BOT_USERNAME`, and refuses to run
   if a webhook is set (long polling would silently receive nothing).
2. `DEVIN_ALLOWED_USERS` / `DEVIN_ALLOWED_GROUPS` are the only chats served;
   everything else is denied (private) or silent (groups/channels).
3. In a group the bot answers only when addressed — `/cmd@DEVinlooperbot`, an
   `@DEVinlooperbot` mention (with or without a command after it), or a reply
   to one of its messages — because it shares the room with other Looper bots.
   An allowlisted ROOM is authorized as a room: every member may use it.
4. Allowlists are read from `Environment=`; **quote any multi-value line**
   (`Environment="DEVIN_ALLOWED_GROUPS=-1001 -1002"`). systemd splits an
   unquoted value on whitespace and silently drops everything after the first
   token, which looks exactly like a working config:

   ```sh
   systemctl show looper-devin -p Environment    # check what REALLY loaded
   ```

## Install (on the VPS, as root)

```sh
useradd --system --home /srv/looper-agents/devin --shell /usr/sbin/nologin looper-devin
install -d -o looper-devin -g looper-devin /srv/looper-agents/devin/{app,state,venv}

# Copy architect/ and devin/ into app/ (done by the deploy step), then the unit:
install -m 0644 looper-devin.service /etc/systemd/system/looper-devin.service

# Encrypted credential — the token is written to systemd-creds, never to a
# plaintext file. Prompt for it; do not pass it on the command line.
systemd-creds encrypt --name=telegram_token - /etc/credstore.encrypted/looper-devin.token

# Optional: a GitHub PAT enables /audit + /debug + /bundle on PRIVATE repos.
# Same pattern (only needed if private-repo work is wanted; without it those
# paths refuse clearly, and the upload path still covers private code).
systemd-creds encrypt --name=github_token - /etc/credstore.encrypted/looper-devin.github

# Optional: the /bundle + upload SEALING KEY. Without it, sealing refuses
# (never a default passphrase) while auditing still works. Use your OWN
# passphrase and keep it in a password manager: it is the only way to open a
# sealed bundle, and it must never travel through chat.
systemd-creds encrypt --name=bundle_passphrase - /etc/credstore.encrypted/looper-devin.bundle

systemctl daemon-reload
systemctl enable --now looper-devin.service
systemctl status looper-devin.service --no-pager
```

The unit ships `LoadCredentialEncrypted=telegram_token:…` and (commented)
`LoadCredentialEncrypted=github_token:…` plus
`LoadCredentialEncrypted=bundle_passphrase:…`. Uncomment a line and `chmod 600`
its encrypted file once the credential is provisioned; each feature fails
closed until then.

## Verify

- `systemctl is-active looper-devin` → `active`
- `journalctl -u looper-devin -n 50` → identity guard passed, no errors
- DM the bot `/start` (after opening the chat) and `/help`
- In the group, `/audit@DEVinlooperbot https://github.com/<owner>/<repo>`
- `/debug@DEVinlooperbot https://github.com/<owner>/<repo>` and
  `/map@DEVinlooperbot https://example.com`; `/doctor@DEVinlooperbot`
- DM `/bundle https://github.com/<owner>/<repo>` → one `.tar.gz.enc` back
  (refuses without the sealing key; refuses groups by design)
- DM a `.zip` / `.tar.gz` **as a document** → static audit, plus the sealed
  bundle when the sealing key is provisioned
- Live check of the group route against the real credentials (its group replies
  are captured, never sent, so proving the route cannot spam the room):
  `systemd-run --pipe --wait --collect --property=EnvironmentFile=/tmp/devin-env
  --property=LoadCredentialEncrypted=telegram_token:/etc/credstore.encrypted/looper-devin.token
  … venv/bin/python app/devin/scripts/live_group_check.py`
- Offline proof scripts (passphrase read from the env, never printed):
  `DEVIN_LIVE_PW=… venv/bin/python devin/scripts/live_pack_check.py` and
  `DEVIN_LIVE_ALLOW_SECRETS=1 DEVIN_LIVE_PW=… venv/bin/python devin/scripts/live_upload_check.py`

## Non-goals

No spend, no wallet, no on-chain writes, no LLM prompt execution, no shell or
interpreter execution of anything in an audited repository or upload, and no
autonomous deployment or publishing of any artifact. This unit only serves
Telegram and performs static, read-only inspection; sealed bundles are a handoff
artifact a human decides what to do with.

A sealed bundle is symmetric AEAD (chacha20-poly1305 + scrypt) for a passphrase
holder. It is not a signature, not a key exchange, and not forward-secret, and
the language inventory is honest breadth (identification by extension and
manifest), not semantic understanding of every project.
