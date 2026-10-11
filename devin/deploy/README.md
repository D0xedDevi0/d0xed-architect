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
3. In a group the bot answers only when addressed (`/cmd@DEVinlooperbot` or a
   reply to one of its messages) — it shares the room with other Looper bots.

## Install (on the VPS, as root)

```sh
useradd --system --home /srv/looper-agents/devin --shell /usr/sbin/nologin looper-devin
install -d -o looper-devin -g looper-devin /srv/looper-agents/devin/{app,state,venv}

# Copy architect/ and devin/ into app/ (done by the deploy step), then the unit:
install -m 0644 looper-devin.service /etc/systemd/system/looper-devin.service

# Encrypted credential — the token is written to systemd-creds, never to a
# plaintext file. Prompt for it; do not pass it on the command line.
systemd-creds encrypt --name=telegram_token - /etc/credstore.encrypted/looper-devin.token

# Optional: a GitHub PAT enables /audit + /debug on PRIVATE repos. Same pattern
# (only needed if private-repo work is wanted; the bot works without it).
systemd-creds encrypt --name=github_token - /etc/credstore.encrypted/looper-devin.github

systemctl daemon-reload
systemctl enable --now looper-devin.service
systemctl status looper-devin.service --no-pager
```

The unit ships `LoadCredentialEncrypted=telegram_token:…` and (commented)
`LoadCredentialEncrypted=github_token:…`. Uncomment the `github_token` line and
`chmod 600` the encrypted file once a PAT is provisioned.

## Verify

- `systemctl is-active looper-devin` → `active`
- `journalctl -u looper-devin -n 50` → identity guard passed, no errors
- DM the bot `/start` (after opening the chat) and `/help`
- In the group, `/audit@DEVinlooperbot https://github.com/<owner>/<repo>`
- `/debug@DEVinlooperbot https://github.com/<owner>/<repo>` and
  `/map@DEVinlooperbot https://example.com`; `/doctor@DEVinlooperbot`

## Non-goals

No spend, no wallet, no on-chain writes, no LLM prompt execution, and no shell
execution of anything in an audited repository. This unit only serves Telegram
and performs static, read-only inspection of GitHub repositories.
