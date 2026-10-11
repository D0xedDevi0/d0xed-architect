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
| `wall_s` | runner-internal elapsed seconds; excludes Python import, process startup, and Architect's pre-timer robots/llms discovery |
| `driver_wall_s` | subprocess launch through exit, including imports and browser startup |
| `content_marker_pages` | pages whose extracted markdown contains the literal target marker (not raw HTML) |
| `process_exit_code` | actual runner exit status; nonzero output cannot count as metrics |
| `bytes` | processed response-body byte length (not network transfer bytes; representations differ by tool) |
| `edges` | internal links discovered (the graph) |
| `markdown_chars` | total LLM-ready markdown produced |
| `robots_found` / `llms_found` | whether access policy was read |
| `peak_rss_mb` | Python runner's peak RSS only (`RUSAGE_SELF`); Chromium child processes excluded |

Each tool runs in **its own interpreter** (`compare.py` shells out), so
Python-runner RSS is separately attributable. The reported RSS excludes
Chromium children and must not be compared as total browser memory.

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

## Static + JS-dependent matrix (bounded observation)

```bash
export PLAYWRIGHT_BROWSERS_PATH=/opt/data/.cache/ms-playwright
.venv/bin/python bench/benchmark_matrix.py bench/targets-static-js.json \
  --max-pages 2 --depth 1 --repetitions 1 \
  --output bench/results/2026-10-11-static-js-matrix.json
```

`results/2026-10-11-static-js-matrix.json` is the raw artifact; the command
uses exclusive creation and will refuse to overwrite it. It records the exact
commit at execution (`f00daa4de604d8c542624a83bd206a12fea31953`), timestamps,
per-run exit codes, runner wall time, subprocess wall time, RSS, bytes, pages,
and extracted-markdown marker presence. It was run against `example.com/`
(robots: explicit 404, treated as absent) and `quotes.toscrape.com/js/`
(robots: explicit 404, treated as absent). One cold subprocess per tool/mode,
no persistent cache; six runs, one repetition each, capped at two pages and
one link depth. The browser path on this host was
`/opt/data/.cache/ms-playwright`. These sites may change between runs.

Observed **within this small sample**:

- Static example: Architect HTTP and ladder reached 1 page with the
  `Example Domain` markdown marker; Crawl4AI reached 1 page without that exact
  markdown marker. All are flagged as one-page frontiers, **not** throughput
  evidence. The missing marker is an extraction difference, not proof that
  Crawl4AI failed the page.
- JS quotes: Architect HTTP reached 2 pages but lacked `Albert Einstein` in
  extracted markdown; ladder reached 2 with the marker on 2 pages; Crawl4AI
  reached 2 with the marker on both. This is the expected browser-content
  distinction for this selected site, not a general accuracy estimate.
- Subprocess elapsed (`driver_wall_s`): static Architect HTTP 0.485 s,
  ladder 0.481 s, Crawl4AI 4.551 s; JS Architect HTTP 2.563 s,
  ladder 5.614 s, Crawl4AI 5.582 s. A single cold run per cell is not a
  distribution and cannot establish a speed winner. Runner `wall_s` excludes
  interpreter imports; do not compare it as end-to-end latency.

The matrix compares three **postures**, not identical engines: Architect
HTTP-only, Architect HTTP-first/guarded browser escalation, and Crawl4AI's
sequential `arun` browser loop. Architect strictly loads robots and guards
queued/redirected/browser requests; Crawl4AI retains its separate default
robots behavior (`check_robots_txt=False`). The published targets each returned
an explicit 404 for `robots.txt` before execution. The matrix now refuses
Crawl4AI mode when strict robots lookup returns a policy or an error; it does
not silently run the default-robots-off browser against a restrictive site.
This conservative seed-origin check is not a per-hop guard: Crawl4AI's
independent default does not enforce our redirect/subrequest policy, and the
matrix is not an arbitrary-target access-safety guarantee. Crawl4AI `arun_many` throughput is
not measured. The marker is a literal substring in extracted markdown, so
paraphrases, formatting differences, and content changes can produce false
negatives; it is not a semantic extraction score. No anti-bot or paid x402
sites were included. Typed extraction quality is evaluated separately below.

## Robots-gated one-page snapshots

`results/robots-gated-d0xeddev-1page.json` and
`results/robots-gated-baseddoom-1page.json` preserve separate post-fix runs
(`ARCH_MODE=ladder`, `max_pages=1`, `depth=0`, cold process; no persistent
cache). They are **single live observations**, not speed distributions or
like-for-like robots-policy comparisons. Architect checks queued page paths
against the discovered `robots.txt` before requesting them; Crawl4AI runs
with its default robots setting. A discovered denied URL counts as skipped.

Architect's crawl paths now check queued URLs and HTTP redirect hops against
per-origin rules before fetching; HTTP cache hits are gated too. The paid
transport uses the same per-hop guard. In ladder mode, Chromium's CDP request
interception gates page redirects, script navigation, and subrequests; service
workers and secondary pages are blocked during guarded renders. Local-server
tests assert forbidden destinations receive zero HTTP/browser requests.
Crawl4AI retains its independent default robots setting, so the archived
one-page snapshots are **pre-redirect-fix**, not evidence of new timings.

**Scope:** this is crawl-path access enforcement, not a claim of general
browser isolation or an SSRF-safe arbitrary-URL fetch API. Crawl entry points
fail closed when the initial robots policy is unavailable (except an explicit
404), and they require both starting-site and redirect-origin rules to allow a
page. Ambiguous dot-segment and slash encodings are denied rather than guessed.

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
