# Jev: optional public-page decisions

Jev is a hosted, optional semantic annotation boundary, not a crawler or an agent replacement. Acquisition, robots/model-input policy, public-network URL checks, redirects, extraction, source hashes, permissions and actions remain code-owned. No private repository audit or uploaded archive is sent to Jev.

## Architect

Install the optional extra with `python -m pip install '.[jev]'`. The extra pins `typesafe-sdk==0.7.5`; default installation and existing commands do not require it.

```sh
architect judge-page https://docs.typesafe.ai/introduction \
  --objective 'Find documentation for integrating the Python SDK' \
  --allow-model-input --out /outside/the/repo/jev-receipt.json
```

The URL and objective must be explicit. `--allow-model-input` is operator permission to export bounded public evidence, not permission to override a site's explicit denial. Supply `TYPESAFE_API_KEY` to the process through the credential broker; never put a key in commands or project files. Models are explicitly pinned to `jev-1.13.0` (default) or `jev-1.14.0` via `--model`. No ordinary-LLM substitution occurs.

Use `--offline` for the no-inference path (guarded public-page acquisition still uses the network). Without the SDK, credential, eligible evidence or permission, the receipt records the unavailable/refused state. `--cache-dir /private/outside/repo/jev-cache` is optional and requires an owner-private directory outside source-controlled trees. Cache identity includes option insertion order, exact questions, evidence, model, provider and policy. Cache integrity is not producer authentication against someone who can write the cache.

A receipt preserves source/final URLs, the acquired source SHA-256, bounded literal-source candidate excerpts, configured/returned model, question digest, probabilities and exact confidence metric, usage, request IDs where supplied, timestamps/latency and error/abstention states. Hidden, omitted and nonliteral spans are not represented as complete page coverage. Candidate relevance never changes the crawler frontier, permissions or factual source checks. Existing static extraction and reports are unchanged.

## DEVin /judge

```text
/judge https://docs.typesafe.ai/introduction | Find Python SDK integration guidance
/judge@DEVinlooperbot https://docs.typesafe.ai/introduction | Find Python SDK integration guidance
```

This explicit command consents to exporting the objective and selected public-page excerpts. Never include private data. Only named human operator IDs in `DEVIN_ALLOWED_USERS` can invoke it. The wildcard/open-DM setting and room membership grant no paid Jev access; bots cannot invoke it. Existing public chat, static audits, sealing and crawl commands keep their existing authorization.

Defaults: at most 20 reserved requests per UTC day, a 30-second global cooldown, one Jev attempt per invocation, no automatic retries. `DEVIN_JEV_DAILY_LIMIT` may explicitly select 1–50 requests/day. Reservations survive restart and are not refunded after uncertain failures; a failed fetch may consume a reservation without making an inference call. Request deduplication is scoped to the current UTC-day ledger. Corrupt, insecure or symlinked state fails closed. This is an API-call/size/time control, not an invoice or provider-account-wide monetary cap; independent CLI use has its own limits.

The reply shows shadow outcome, purpose/relevance where returned, model, source hash and receipt ID; full receipts remain private on the server. Neither a positive score nor confidence is a safety verdict. Abstentions remain abstentions. No scheduled Jev jobs, automatic wallet actions, private-code inference or crawler reordering are enabled by this release.

Trust limits: the daily ledger is not tamper-evident against its owning service user (or root). Deleting it initializes a fresh ledger; a same-UID writer could also replace it with a valid empty one. Private permissions and shape validation protect against other users and accidental corruption, not a compromised service identity. An unkeyed integrity digest would not change that threat model. Keep provider-account spend limits separate and preserve state across upgrades/rollback.

The bot's explicit `/judge` invocation supplies the public-input consent that the CLI requires as `--allow-model-input`; neither overrides an explicit site denial. The objective filter is intentionally conservative: even benign questions mentioning secret-related terms may be refused. Rephrase without sensitive terms rather than weakening filtering for this release.

## Service deployment

Keep the existing service unit, Telegram/GitHub/sealing credentials and optional social-model drop-in intact. Provision the Typesafe credential by streaming brokered bytes directly to `systemd-creds encrypt --name=typesafe_api_key - /etc/credstore.encrypted/looper-devin.typesafe` over authenticated SSH. Do not write plaintext key files. Install the optional SDK in DEVin's venv. Stage and test the exact release code as the service user before restart.

Add a separate drop-in (only after the encrypted credential exists):

```ini
[Service]
LoadCredentialEncrypted=typesafe_api_key:/etc/credstore.encrypted/looper-devin.typesafe
Environment=DEVIN_JEV_ENABLED=1
Environment=DEVIN_JEV_STATE=/srv/looper-agents/devin/state/jev
Environment=DEVIN_JEV_DAILY_LIMIT=20
```

The private state directory must belong to `looper-devin` with mode 0700, outside the code tree, and lie under the existing unit's `ReadWritePaths`. Encrypted credentials are resolved from `$CREDENTIALS_DIRECTORY/typesafe_api_key`; local process-env fallback is supported. Logging never prints credentials or request/response bodies. Systemd `EnvironmentFile` variables do not appear in `systemctl show -p Environment`; inspect only permitted nonsecret keys/metadata.

After `daemon-reload` and restart, verify ActiveState/NRestarts, exact deployed source digests, service-user module/SDK availability, configured limits, a bounded real public-page judgment and the resulting private receipt. Update Telegram copy from `devin/report.py` with `devin/scripts/apply_telegram_copy.py`, then independently read back `getMyDescription`, `getMyShortDescription` and `getMyCommands`. Do not run a second poller for a smoke check.

Kill switch: set `Environment=DEVIN_JEV_ENABLED=0` in the Jev drop-in, daemon-reload and restart; normal static/chat capabilities remain. For full rollback restore the pre-release application backup and previous Jev drop-in, retaining the private budget and receipt files so rollback/redeploy cannot reset consumed reservations. Leave all unrelated service drop-ins and credentials untouched.

## Evidence and limitations

Research pins/acquisition coverage and REA source-map evidence are under the separate operator workspace `research/typesafe-jev`. All 12 public organization repositories were inventoried, but this is not an exhaustive security audit of every file or Typesafe's private hosted inference. No public Jev weights or complete drop-in crawler were found. `system-one-adapter-python` is an ordinary-provider adapter, not Jev.

`bench/jev_fixtures.json` explicitly labels authored synthetic expectations. Its live evaluation is a smoke test, not independent human ground truth or proof of production accuracy. All agreed expectations plus abstentions do not establish automatic coverage. Run the full legacy suite, SDK-enabled transport tests, fresh-wheel install/offline checks, independent release review and service-user deployment checks after the final implementation edit.
