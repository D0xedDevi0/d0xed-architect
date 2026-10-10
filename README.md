# 🟦 D0xed Architect

An **identity-declared, x402-paying agentic crawler + code auditor**.
It doesn't ignore the 2026 crawling contract — it implements it.

## Why this exists

The web split into three camps: **block**, **allow**, or **charge**.
Cloudflare's *pay-per-crawl* and the x402 Foundation turned HTTP `402`
into a machine-readable "yes, if". Every other crawler gets 403'd.
D0xed Architect pays, and gets let in.

## What it does

| Layer | Contract it honours |
|---|---|
| `http.py` | robots.txt · content-signals · llms.txt v2 · Web Bot Auth identity headers · HTTP 402 detection |
| `extract.py` | HTML → title/headings/links/code/JSON-LD/emails, stdlib only |
| `trust.py` | indirect prompt-injection firewall, zero-width/bidi/hidden-text detection, provenance score |
| `graph.py` | SQLite site + module graph (nodes/edges, hubs, orphans) |
| `audit.py` | secret scan (12 rules), risky-pattern scan (14 rules), import graph, entrypoints |
| `crypto.py` | AES-256-GCM + scrypt envelope encryption for every report |
| `report.py` | D0xed blueprint-style markdown output |
| `sentinel.py` | deterministic architecture fingerprint (`arch_root`) · Ed25519-signed baseline · 9-class drift diff (modules, import edges, entrypoints, deps) · signed drift reports a third party can verify with only a public key |
| `watch.py` | standing guard: rolling baseline kept outside the audited tree, a tampered baseline is refused (never repaired), append-only drift log, cron-shaped exit codes |
| `viz.py` | deterministic SVG drift map — cyan added · amber modified · red removed · same input, byte-identical output |

## Install

```bash
uv venv .venv && uv pip install --python .venv/bin/python cryptography
```

## Use

```bash
# map a site (respects robots.txt, reads llms.txt first)
.venv/bin/python -m architect.cli crawl https://d0xeddev.com --depth 2 --max-pages 30 --out site.md

# audit a codebase
.venv/bin/python -m architect.cli audit /path/to/repo --out audit.md --graph audit.db

# encrypted, per-user artifact
export ARCHITECT_PASSPHRASE='...'
.venv/bin/python -m architect.cli audit /path/to/repo --out audit.md --encrypt

# decrypt anywhere
.venv/bin/python -m architect.cli decrypt audit.md.enc

# sentinel: fingerprint this tree, then prove what changed against it
.venv/bin/python -m architect.cli sentinel capture . --out baseline.json --sign
.venv/bin/python -m architect.cli sentinel diff . --baseline baseline.json

# drift is advisory (exit 0) unless something was REMOVED — then exit 1
```

`diff` on an unchanged tree prints `no drift (architecture unchanged)` and exits 0.
A signed baseline (`--sign`) is verified before it is trusted; a tampered one is
refused cleanly.

## Typed extraction (opt-in MCP tool)

The `extract_typed(url, schema_json, use_llm=False, max_model_calls=1)` MCP tool
returns schema-shaped values and per-field literal excerpts, locators, methods,
and SHA-256 of fetched source bytes. `scrape_url` still returns markdown. Schemas
are capped at 8 KiB / 16 fields; selectors are declarative (`title`, `h1`,
`description`, `canonical`, `lang`, `headings`, `links`, `text`, `jsonld:<key>`).
Unsupported values are `null`. The new fetch path checks public DNS at each
redirect, validates robots.txt before page fetching, rejects 402 without payment,
and caps responses. Its SSRF defenses rely on the bundled pinned-IP stdlib HTTP
transport; do not replace that transport with an unguarded client in production.

The model path is **off by default**. To use Nous Portal via Hermes OAuth, start
its loopback proxy (in another terminal/session) before calling with
`use_llm=True`:

```bash
hermes proxy start --provider nous --host 127.0.0.1 --port 8901
```

It uses the catalog-tested `deepseek/deepseek-v4.1-flash` model through that
fixed loopback endpoint. No API key is stored in this project. If the proxy is
absent, the model step fails closed and deterministic partial results remain.
At most one 12,000-character / 512-output-token model call processes unresolved
fields; explicitly selected DOM/JSON-LD fields are never guessed by the model.
Every accepted model field must also have a verbatim excerpt in fetched bytes.
For `text` without a hint, the normalized visible text carries an array of
verbatim DOM text nodes as evidence (up to 32 nodes / 1,000 source characters);
larger or entity-decoded pages abstain instead of claiming unsupported evidence.
The legacy markdown parser remains the default; typed-only hidden-content
filtering does not change `scrape_url` output.
Model usage/cost is **provider-reported after the call**, not a certified
pre-call USD ceiling. There is no automatic payment or model call on the default
path. The proxy is a local service; protect the host from untrusted co-tenants.

Run the small fixture quality evaluation separately from crawl-speed benchmarks:

```bash
.venv/bin/python bench/typed_eval.py --mode deterministic
.venv/bin/python bench/typed_eval.py --mode llm --allow-live-model
```

The nine handcrafted fixtures exercise evidence, ambiguity, abstention, hidden
content, and mixed extraction; their scores are *not* a production accuracy
estimate. The paid run reports actual model calls, usage, and provider-reported
cost, or `unknown` if missing. See `docs/superpowers/plans/2026-10-10-typed-extraction.md`.

## Roadmap

- **v0.2** Ed25519 key-directory + RFC 9421 HTTP Message Signatures (real Web Bot Auth)
- **v0.2** x402 settlement: on 402, sign a USDC transfer on Base and retry
- **v0.3** WebMCP tool-calling (call the site's tools instead of scraping)
- **v0.3** serve as an x402-paid endpoint (`/architect/audit`) on api.d0xeddev.com
- **v0.4** MCP server so any agent can drive it
- **v0.5** architecture drift: `sentinel capture` / `sentinel diff` + SVG drift map
- **v0.5** JS/TS import extraction beyond the current best-effort pass
- **Built:** typed, evidence-backed extraction with optional Nous Portal fallback and a separate, small extraction-quality fixture benchmark.
- **After the initial crawler build:** package capabilities into **DEVin**, a builder/architect/debugging agent for Looper #706 with Telegram contract/code/link intake. Identity, authorization, and sandbox gates must be verified before activation. [Design and saved roadmap](docs/superpowers/specs/2026-10-10-typed-extraction-and-devin-roadmap-design.md).

_NFA. DYOR. Built in the open._
