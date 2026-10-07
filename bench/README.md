# bench/ — D0xed Architect vs Crawl4AI, measured

Reproducible head-to-head. The point is to have **numbers we can defend**,
including the ones that make us look slow.

```bash
cd d0xed-architect
export PLAYWRIGHT_BROWSERS_PATH=/opt/hermes/.playwright   # reuse the chromium already on this box
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
  BrowserConfig. Solved by reusing the existing Playwright build at
  `/opt/hermes/.playwright` (revision 1243 matched what our Playwright wants)
  via `PLAYWRIGHT_BROWSERS_PATH` — no 150MB download needed.

## Files

- `tool_architect.py` — our crawler, JSON metrics
- `tool_crawl4ai.py` — Crawl4AI, same BFS policy
- `compare.py` — driver; writes `bench-results.json`
- `bench-results.json` — last run
