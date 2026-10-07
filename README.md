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
```

## Roadmap

- **v0.2** Ed25519 key-directory + RFC 9421 HTTP Message Signatures (real Web Bot Auth)
- **v0.2** x402 settlement: on 402, sign a USDC transfer on Base and retry
- **v0.3** WebMCP tool-calling (call the site's tools instead of scraping)
- **v0.3** serve as an x402-paid endpoint (`/architect/audit`) on api.d0xeddev.com
- **v0.4** MCP server so any agent can drive it

_NFA. DYOR. Built in the open._
