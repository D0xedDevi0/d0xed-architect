# The web-crawler landscape in 2026, and where D0xed Architect fits

Written 2026-10-07. Every number below is either **cited** (someone else
measured it, and I say who) or **measured on this box** (reproducible with
`bench/compare.py`). Vendor marketing numbers are labelled as vendor claims.

---

## 1. The real split is architecture, not features

Feature tables make every crawler look the same. The thing that actually
determines speed, cost and failure mode is **what sits in the request path**:

| Architecture | Examples | Request path | Consequence |
|---|---|---|---|
| **HTTP-first** | Scrapy, our architect, `crw` | socket → HTML | fast, cheap, blind to JS |
| **Browser-first** | Crawl4AI, Playwright, Puppeteer | socket → **Chromium** → HTML | renders SPAs, costs ~2GB RAM and ~10x latency |
| **Managed API** | Firecrawl, Bright Data, Scrapfly, Context.dev | your code → vendor fleet | someone else runs the browsers and proxies |

Most "X vs Y" comparisons are really comparing layers. Crawl4AI and Firecrawl
are both fetch-and-convert tools; Firecrawl's `/extract` is a *different job*
(typed records) bolted onto the same API. Comparing them on extraction quality
conflates retrieval with structuring.

**The headline cost of the browser-first choice**, measured across two
independent 2026 benchmarks:

- **Throughput** (Spider.cloud, 1,000 real URLs, corpus average):
  HTTP-first **74 pages/s** · Firecrawl **16 pages/s** · Crawl4AI **12 pages/s**
- **Time to first result** on a static page (same benchmark):
  HTTP-first **45ms** · Firecrawl **310ms** · Crawl4AI **480ms**
- **Idle footprint** (vendor docs): browser stacks carry a Chromium heap;
  Crawl4AI's Docker image is ~2GB, Firecrawl's ~500MB.

That is the trade in one line: **a browser buys JS rendering and pays roughly
6x the latency and 20x the idle memory before it fetches anything.**

---

## 2. The players, honestly

### HTTP-first / framework
- **Scrapy** — the old reliable. Twisted-based, unmatched for large structured
  crawls, but it is a *framework*: you write spiders, you own rendering,
  retries, dedupe. No MCP, no LLM output.
- **crw (fastCRW)** — Rust, single static binary, no headless browser in the
  request path. Claims **63.74% truth-recall (522/819)** and **91.8% scrape
  success** on its public set, and ships a built-in MCP server. Closest thing
  to our architecture in the commercial space.
- **Jina Reader** — one job, done well: URL → markdown, free tier, no
  crawling/graphing.

### Browser-first
- **Crawl4AI** — Apache-2.0, Python, Playwright under the hood. The default
  choice for a self-hosted RAG pipeline. Real strengths: `MemoryAdaptiveDispatcher`
  (pauses above a memory threshold, e.g. 90%), `arun_many` with rate limiting,
  BM25 filtering to cut tokens, local LLM support via Ollama. Real cost: you
  operate Chromium, queues, and proxies yourself.
  **Robots trap:** `check_robots_txt` defaults to **False** — compliance is
  opt-in, so the default posture is to ignore robots.txt.
- **Playwright / Puppeteer** — libraries, not crawlers. Nothing about dedupe,
  politeness, or output shape.

### Managed
- **Firecrawl** — AGPL-3.0 open core, credit-based. 1 credit/page for
  scrape/crawl/map; free tier ~1,000 credits/mo, Hobby ~$16–19/mo (5k),
  Scale ~$599/mo (1M). Its `/extract` (schema or prompt → JSON) is what
  people actually buy. Official MCP server. 403/404 responses still cost a credit.
- **Bright Data / Scrapfly / ZenRows** — you are buying *access*: residential
  proxy pools and anti-bot defeat. Bright Data from ~$500/mo; Scrapfly advertises
  99.99% success across 130M+ proxies. If your target fights back, this layer is
  the product.
- **Apify** — ~60,000 prebuilt Actors behind an MCP server. Breadth, at the cost
  of a different output shape per Actor.

### The 2026 shift that matters most
**MCP moved from novelty to table stakes.** Firecrawl, Bright Data, Scrapfly,
ZenRows, Skyvern, Apify and Context.dev all now expose MCP servers, and new
entrants (CrawlForge, claiming 31 discoverable tools) are *MCP-native first*.
The selection criterion is shifting from "what does it scrape" to
**"can my agent discover and call it without glue code."**

---

## 3. Where D0xed Architect sits

We are deliberately **HTTP-first**, and that is the defensible choice:

- **We are the fast path.** No Chromium in the request path means our latency
  profile is the 45ms class, not the 480ms class. For repo docs, blogs, and
  most marketing sites, rendering JS is wasted work.
- **We are robots-aware by default.** `check_access` reads robots.txt and
  llms.txt *before* any page fetch. Crawl4AI's default is the opposite. Compliance
  is our default, not a flag you remember to set.
- **We carry evidence other crawlers don't.** Findings ship with `file:line`,
  the literal snippet, a snippet hash and a file hash, plus a manifest root —
  so a caller can **re-verify** a report instead of trusting it. No crawler in
  the table above does this; they return content, not claims you can check.
- **We ship MCP from day one** — 5 tools (`check_access`, `scrape_url`,
  `map_site`, `audit_path`, `verify_report`), stdio, no per-page fee.

What we **do not** have, stated plainly:
- **No JS rendering.** SPAs return shells. This is the real cost of the choice.
- **No proxy/anti-bot layer.** Blocked sites stay blocked.
- **No `arun_many`-class concurrency tuning.** We use a fixed small thread pool.
- **No typed extraction.** We return markdown, not schema-shaped JSON.

---

## 4. What to build next, in priority order

1. ~~**Escalation, not replacement.**~~ **BUILT — see §6.** `architect/escalate.py`
   keeps HTTP-first as the default and escalates to a browser only when the
   *already-fetched* HTTP response classifies as a JS shell. crw's ladder shape,
   implemented and measured.
2. ~~**Concurrency you can tune.**~~ **BUILT — see §7.** `architect/limiter.py`:
   per-host AIMD, minimum interval, `Retry-After`, and robots `Crawl-delay` as a
   floor. Deliberately a *rate limiter*, not a memory-adaptive dispatcher.
3. ~~**Caching.**~~ **BUILT — see §7.** `architect/cache.py`: conditional-GET /
   ETag revalidation, sqlite-backed so it persists across runs.
4. **`/extract`-style typed output.** Markdown is the right default, but agents
   often want a schema. This is where Firecrawl's value concentrates.
5. **Publish the benchmark.** Nobody in this space ships reproducible
   numbers with the harness attached. `bench/compare.py` is that, and keeping it
   honest (same BFS, same page cap, separate processes) is a differentiator.

---

## 5. Measured on this box

`bench/compare.py`, 2026-10-07. Target `https://d0xeddev.com`. Same origin,
same page cap (25), same depth (2), same BFS link policy, www-normalised hosts,
each tool in its **own process** so peak RSS is attributable. Raw output:
`bench/bench-results.json`. Full caveats: `bench/README.md`.

| Metric | D0xed Architect | Crawl4AI | Ratio |
|---|---|---|---|
| Pages crawled | **25** | **25** | — |
| Wall time | **8.73 s** | 23.77 s | **2.7x faster** |
| Throughput | **2.86 pages/s** | 1.05 pages/s | **2.7x** |
| Peak RSS | **66.1 MB** | 132.2 MB | **2.0x lighter** |
| HTML bytes pulled | **1,061,725** | 1,811,688 | 1.7x less |
| Internal edges found | 265 | 94 | (see note) |
| Markdown produced | 76,155 chars | 119,317 chars | — |
| Reads robots.txt | **yes** | no (default) | — |

Both tools fetched all 25 pages, so this is a like-for-like throughput result
rather than one tool giving up early.

**The honest reading of this table:**

- The **2.7x** is real but it is the *architecture* winning, not cleverness.
  We never start a browser; Crawl4AI starts Chromium and pays for it on every
  page. On `d0xeddev.com` — static marketing pages — rendering is pure
  overhead. **On a heavy SPA this result would reverse**, and we would be the
  ones returning empty shells.
- The **2x memory** difference is the same story: 66 MB of Python vs a Chromium
  heap. This is exactly why the crawl runs comfortably on a small VPS.
- Crawl4AI produced **more markdown** (119k vs 76k chars) — it is capturing the
  rendered DOM, which is richer. That is the thing you are paying 2.7x for, and
  on JS-driven pages it is worth it.
- The **edges** gap (265 vs 94) is *not* a clean win: the two tools define and
  dedupe "internal link" differently, so treat that row as "different", not
  "better".
- **This is one target, one size, one day.** It is a sanity check with a
  reproducible harness attached, not a benchmark you should quote as a general
  claim. Re-run it on your own targets.

See `bench/README.md` for the exact reproduction command and the ways the
comparison is still not fair.

---

## 6. The escalation ladder (built)

`architect/escalate.py` — HTTP first, escalate only when needed:

```
http()  ->  looks_js_dependent()  ->  [render()]  ->  Response
```

The classifier scores the **already-fetched** HTTP response; anything below the
threshold is served straight from HTTP. Signals: thin visible text, near-empty
body, script-dominated payload, SPA mount markers (`#root`, `#app`, `__NEXT_DATA__`,
`ng-version`), a `<noscript>` asking for JavaScript, and module scripts with no text.

**Measured behaviour (2026-10-07):**

| Target | Verdict | HTTP text | Notes |
|---|---|---|---|
| `d0xeddev.com` (25 pages) | **0–1 escalations** | full | ladder added ~2.3s, i.e. one browser launch, not per page |
| `app.uniswap.org` | **escalated** (score 7) | 64 chars | recovered 632 chars of real content only after JS ran |
| `react.dev` | http-only (score 0) | 10,708 chars | correctly not rendered |
| `tailwindcss.com` | http-only (score 0) | 6,921 chars | correctly not rendered |
| `vercel.com` | http-only (score 0) | 1,729 chars | correctly not rendered |

Real crawl, same 25 pages:

| Mode | Wall | RSS | Escalations |
|---|---|---|---|
| plain (HTTP only) | 9.05 s | 60.3 MB | 0 |
| `ARCH_MODE=ladder` | 11.39 s | 80.6 MB | 1 |

**Read it honestly:**

- The extra **2.3s is a single browser launch**, not a per-page cost. That is the
  entire point of the design: the ladder's overhead is near-fixed, so it
  amortises away on big crawls and stays small on small ones.
- **The escalation rate on this site was not stable across runs** (1 of 25 in the
  parallel crawl, 0 in two verification scans). The likely cause is a thin or
  partial response under 6-way parallel fetching classifying as a shell. That is
  a **false-positive cost**, and it is the main risk in this design: a wasted
  browser launch, never wrong content. Worth measuring properly before trusting
  the rate.
- An `EscalationBudget` caps renders per crawl so a pathological site cannot turn
  a cheap crawl into a browser farm. When the budget is exhausted it **falls
  back to the HTTP response** and labels the verdict `budget-exhausted` — it
  degrades, it does not fail.
- `allow_render=False` gives a hard HTTP-only mode for callers who never want a
  browser, and `force_render=True` for the opposite.

**Known limits:** escalation is decided from HTTP alone, so a page that serves
*full* HTML and *also* enriches itself with JS will not be rendered — by design,
since we cannot know what we are missing without paying for the browser. And the
render wait is a fixed `domcontentloaded` + 350ms settle, not a network-idle
wait, so slow-hydrating apps may still come back partial.

---

## 7. Caching and politeness (built)

### `architect/cache.py` — conditional GET

sqlite-backed, so the cache is a real file across runs rather than per-process.
Two distinct wins: *freshness* (`max-age`) serves with zero network, and
*revalidation* (`ETag` / `Last-Modified`) sends `If-None-Match` so an unchanged
page costs a 304 instead of a full body.

**Measured, warm re-crawl of `d0xeddev.com` (25 pages):**

| | cold | warm |
|---|---|---|
| wall | 9.29s | 8.66s |
| body transferred | ~1.05 MB | **~0.002 MB** |
| pages from cache | 0/25 | 25/25 |

**The honest read: a bandwidth win, not a latency win.** The site sends
`cache-control: max-age=0, must-revalidate`, so nothing is ever *fresh* and every
page revalidates. A 304 still costs a full round-trip, and on a small fast site
latency is round-trip-bound, not byte-bound. The prediction "repeat crawls are
nearly free" was **right on bytes, wrong on time**. Where an origin actually
sends a `max-age`, the zero-network path is real and is unit-tested
(`fresh hit makes NO network call`).

The assertion that matters more than any number: a page that **changed** must
return the new body, never the stale one. A cache that silently serves stale
content corrupts every downstream report, so it has its own test.

### `architect/limiter.py` — adaptive per-host concurrency

- **AIMD**: additive increase after 5 clean results, multiplicative decrease on
  pushback. Slow up, fast down.
- **Per-host minimum interval**, with robots.txt `Crawl-delay` honoured as a
  **floor** — a smaller declared delay can never speed us past our own default.
- **`Retry-After`** parsed in both legal forms (delta-seconds and HTTP-date).
- **429 vs 503 — the distinction that turned out to matter.** Only a 429 is
  rate-limit pushback. A 503/500/405 is an outcome for *one URL*, never a
  host-capacity signal.

### The bug this section exists to record

Wiring the limiter into `map_site` turned a **~9s crawl into 193s**; the 25-page
crawl then blew past a 280s timeout. Root cause, found by measuring rather than
guessing: the site's page lists **~20 API endpoints returning 503/500/405**.
Every 503 was routed to `on_throttled()`, which compounds `2**n` host-wide
backoff — by the sixth, 64 seconds per request, serialising the entire crawl
behind dead endpoints.

Three fixes, each now pinned by a test:

1. only **429** drives throttling; 5xx/405/timeouts are recorded through
   `on_error()` and deliberately do **not** touch the concurrency limit or set
   host backoff;
2. exponential backoff is **capped**, never unbounded `2**n`;
3. `on_success()` **decays** the penalty counter, so penalties cannot accumulate
   across unrelated URLs over a whole crawl.

Plus a smaller one: `Retry-After: 0` means "retry now", but `0` is falsy, so a
`if retry_after else ...` check silently promoted it to exponential backoff.

Result: **193s → 9.5s** for `8/1`; `25/2` now completes in 9.5s.

**Generalise the lesson:** a per-URL error and a host-wide backpressure signal
are different things, and conflating them makes the crawler punish every healthy
URL for one dead one. Every test was green while this was broken — none of them
covered the integration path. Passing unit tests on a component say nothing
about the component once it is wired in.

**Still open:** this is a *rate* limiter, not a memory-adaptive dispatcher. There
is no backpressure from our own memory use, so a very large frontier could still
grow RSS. That remains item 2's unbuilt half.


