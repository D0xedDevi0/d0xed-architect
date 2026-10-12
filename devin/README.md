# DEVin — read-only Telegram auditor (Looper #706 / ERC-8004 agent 87226)

Read-only, bounded, allowlisted Telegram bot. **Offline by default** —
importing the package performs no network I/O and holds no credentials. The
only network entry point is `python -m devin`, which refuses to start without
a token and allowlist.

**Persona:** the bot's name, voice, Telegram Description/About, `/start` banner,
`/help`, and command menu are derived from Looper #706's real on-chain metadata
and live in one place — see [`PERSONA.md`](PERSONA.md) and the copy constants in
`devin/report.py`. Change copy there, never by hand in Telegram.

## Configuration (environment ONLY — fail-closed when unset)

| Variable | Required | Meaning |
|---|---|---|
| `DEVIN_BOT_TOKEN` | yes | Telegram bot token (format-checked, never logged/echoed) |
| `DEVIN_ALLOWED_USERS` | yes | comma-separated Telegram user IDs (DM allowlist) |
| `DEVIN_ALLOWED_GROUPS` | no | comma-separated group chat IDs (group allowlist) |

Missing/invalid token or users list → `ConfigError` → no startup.

## Commands (bounded)

- `/start` — opens with Looper #706's artwork + the welcome caption (falls back
  to a plain text banner if the photo is rejected).
- `/help` — command list.
- `/lore` — who DEVin is: his on-chain identity, class, and trait stack, stated
  from bundled data (no fetch).
- `/audit https://github.com/<owner>/<repo>` — static-only scan of a repository
  (secrets + risky patterns, `path:line` + masked snippet + sha256 receipts).
  Rejects any other scheme/host/subpath. Public repos work by default; a
  **private** repo works only when a GitHub token is configured (see below).
- `/debug https://github.com/<owner>/<repo>` — the deep static
  architecture/debug report: languages, entrypoints, top-imported modules and
  import cycles, dependency manifests, CI workflows, test files, TODO/FIXME
  counts, plus the secret/risk findings.
- `/map <url>` — a bounded, **robots-respecting** map of a public site: the seed
  title plus its same-origin, robots-allowed links. Fails closed if robots.txt
  is unavailable; never follows off-origin links.
- `/doctor` — bounded self-diagnostics (identity, allowlist counts, webhook
  status, whether a GitHub token is configured — boolean only; limits).

## Optional GitHub token (private repos)

`/audit` and `/debug` accept an optional token so **private** repos can be
inspected. It is resolved like the bot token — first
`$CREDENTIALS_DIRECTORY/github_token` (production), else `DEVIN_GITHUB_TOKEN`
(local) — and is sent **only** as an `Authorization: Bearer` header, **only** to
`api.github.com` / `codeload.github.com`. It is never logged, echoed, placed in
message text, or included in any finding/report/error. With no token a private
repo is a clear refusal.

| Variable | Required | Meaning |
|---|---|---|
| `DEVIN_GITHUB_TOKEN` | no | GitHub PAT for private-repo `/audit` + `/debug` (never printed) |

## Security properties

- **Static-only**: repo source is decoded and regex-scanned; nothing is
  executed. No subprocess, no eval/exec, no LLM prompt execution.
- **No spend / no wallet**: the package imports no `architect.auth` / `x402` /
  `vault` / `escalate` / `contract` / `swarm` modules (guard-tested).
- **SSRF-safe fetch**: GitHub fetches reuse `architect.safe_fetch` (public-IP-
  only DNS pinning, no userinfo, standard ports, allowlisted hosts, redirect
  re-validation, bounded response size).
- **Fail-closed access**: non-allowlisted private senders get one `Access denied.`;
  denied groups/channels get silence.
- **Fail-closed startup**: `getMe` identity is pinned; a wrong token or a set
  webhook aborts startup instead of polling into the void.
- **Shared-group etiquette**: in a group the bot replies only when addressed
  (`/cmd@BotName` or a reply to one of its messages).
- **Token handling**: read from a systemd encrypted credential
  (`$CREDENTIALS_DIRECTORY/telegram_token`) in production, a plain env var only
  for local runs; never logged, echoed, or sent as message text. An optional
  GitHub token (`$CREDENTIALS_DIRECTORY/github_token`) is host-gated to
  `api.github.com`/`codeload.github.com` and never appears in output.
- **Receipts**: every finding carries `path:line`, a secret-masked snippet, and
  sha256 receipts (file + snippet); the report is labelled `STATIC-ONLY`.
- **Limits**: message length, repo file count, per-file bytes, total bytes,
  findings count, reply length, HTTP timeouts, redirect hops — all capped.

## Tests

```bash
.venv/bin/python -m unittest discover -s tests -p 'test_devin_*.py' -v
```

Local fixtures + mocked HTTP only; no network, no real credentials.

## Run

Production reads the token from a systemd encrypted credential
(`$CREDENTIALS_DIRECTORY/telegram_token`); locally, a plain env var works:

```bash
DEVIN_BOT_TOKEN=... DEVIN_ALLOWED_USERS=... [DEVIN_ALLOWED_GROUPS=...] \
  [DEVIN_BOT_ID=... DEVIN_BOT_USERNAME=...] python -m devin
```

At startup the bot verifies its own identity (`getMe`) against the pinned
`DEVIN_BOT_ID`/`DEVIN_BOT_USERNAME` and refuses to run if a webhook is set.
In a group it answers only when addressed (`/cmd@BotName` or a reply to it).
See `deploy/` for the hardened systemd unit. This hosted container cannot host
a persistent bot; it runs on the VPS like the other Looper companions.
