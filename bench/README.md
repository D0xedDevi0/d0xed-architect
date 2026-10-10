# bench/ — D0xed Architect vs Crawl4AI, measured

Reproducible head-to-head. The point is to have **numbers we can defend**,
including the ones that make us look slow.

```bash
cd d0xed-architect
export PLAYWRIGHT_BROWSERS_PATH=/opt/data/.cache/ms-playwright   # installed for this host; override as needed
.venv/bin/python bench/compare.py https://d0xeddev.com 25 2
# -> bench/bench-results.json
```

## What is measured

| Field | Meaning |
|---|---|
| `pages` | pages actually fetched and parsed |
| `wall_s` | end-to-end seconds, including process + browser startup |
| `bytes` | HTML bytes pulled off the wire |
| `edges` | internal links discovered (the graph) |
| `markdown_chars` | total LLM-ready markdown produced |
| `robots_found` / `llms_found` | whether access policy was read |
| `peak_rss_mb` | peak resident memory of that process |

Each tool runs in **its own interpreter** (`compare.py` shells out), so peak
RSS is attributable and one tool's imports cannot inflate another's memory.

## Why it is fair

- **Same BFS policy**: same origin, same `max_pages`, same `depth`, same
  "follow internal links only" rule, same `#fragment` stripping.
- **Same host normalisation**: `_host()` strips `www.`. This matters — see the
  bug note below.
- **Same cache posture**: Crawl4AI runs `CacheMode.BYPASS`, so it is not
  scored on cached content.
- **Default posture for each tool**: we do not enable Crawl4AI's
  `check_robots_txt` (default `False`) and we do not disable our own robots
  handling. Each is measured as it ships, which is the honest comparison —
  but it does mean the robots row is not like-for-like.

## Where it is still NOT a fair fight (read this)

1. **Different architectures, on purpose.** We are HTTP-first; Crawl4AI drives
   a real Chromium. On a site that needs no JS, that is a straight penalty to
   Crawl4AI. On a heavy SPA it would reverse — we would return shells and it
   would return content. **Do not generalise one target's result to "faster
   than Crawl4AI."**
2. **Crawl4AI is running only its own single-page `arun` in a loop here.** Its
   real throughput story is `arun_many` + `MemoryAdaptiveDispatcher`, which we
   are not exercising. Our number is close to our best case; theirs is not.
3. **Browser startup is included in Crawl4AI's wall time** and is a fixed cost
   that amortises over larger crawls. At 25 pages it hurts them; at 5,000 it
   would not.
4. **No anti-bot targets.** Neither tool is being tested against Cloudflare or
   DataDome. Crawl4AI (and any proxy-backed tool) would be the only option there.

## Bugs this harness caught

- **The `www` trap.** `d0xeddev.com` 307-redirects to `www.d0xeddev.com`. A
  strict `target.startswith(origin)` test rejected every internal link, and the
  first run reported Crawl4AI crawling **1 page, 0 edges** — i.e. it looked
  *fast* precisely because it was doing nothing. Fixed with `_host()`
  comparison in both runners. If a crawler ever reports suspiciously few
  pages, check redirects before believing it.
- **`BrowserConfig` has no `executable_path`.** crawl4ai resolves its browser
  through Playwright, so pointing it at `/usr/bin/chromium` is not possible via
  BrowserConfig. Playwright revision 1243 was reused originally; on this
  host its previous `/opt/hermes/.playwright` path disappeared, so the same
  revision was installed to persistent `/opt/data/.cache/ms-playwright`. Set
  `PLAYWRIGHT_BROWSERS_PATH` to whichever installed path exists.

## Typed extraction quality benchmark (separate from speed)

```bash
.venv/bin/python bench/typed_eval.py --mode deterministic
# Explicitly opt in to live, paid model calls; start `hermes proxy start --provider nous --port 8901` first:
.venv/bin/python bench/typed_eval.py --mode llm --allow-live-model
```

`typed_fixtures.json` has nine handcrafted local pages: static data,
conflicting JSON-LD, missing field, visible prompt injection plus hidden
content, SPA shell, generic author, robots denial, `ai-input=no`, and mixed fields. `typed_eval.py` counts
true/false positives, recall, abstention accuracy, model calls, tokens,
wall time, and provider-reported cost. The handpicked sample is too small to
estimate production accuracy; deterministic and live scores are distinct.
`typed-results.json` is generated from a real run, not made-up estimates.

The exact `deepseek/deepseek-v4.1-flash` ID was listed by the live
`GET /v1/models` endpoint of Hermes's Nous OAuth loopback proxy. A direct
`POST /v1/chat/completions` returned HTTP 200 with that exact served model,
field JSON, usage, and nonzero provider-reported cost. The alternative
`qwen/qwen3.8-flash` was also tested (HTTP 200), but default remains DeepSeek.
The last nine-fixture live run used three model calls / 397 input tokens /
34 output tokens and reported `$0.0001599`. These are **observed** values,
not a rate guarantee or certified pre-call USD ceiling. The provider's
catalog pricing and actual billed usage can differ, so the code enforces
one call, input/output caps, and no hidden retry instead of claiming a hard
monetary cap. All model failure paths abstain; no card, key, or raw response
headers are written to result artifacts.

## Files

- `tool_architect.py` — our crawler, JSON metrics
- `tool_crawl4ai.py` — Crawl4AI, same BFS policy
- `compare.py` — driver; writes `bench-results.json`
- `bench-results.json` — last run
