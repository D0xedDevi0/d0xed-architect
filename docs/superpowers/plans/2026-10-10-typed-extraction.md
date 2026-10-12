# Typed Extraction Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship an opt-in MCP typed extractor that returns evidence-backed, schema-shaped fields, with bounded Nous Portal fallback for unresolved fields and a reproducible accuracy evaluation.

**Architecture:** Validate the caller's schema and safely fetch only permitted pages; extract literal facts deterministically, then optionally ask a constrained model to propose unresolved values. Validate model suggestions against verbatim fetched-source evidence. The current markdown tool remains unchanged. Distinct modules isolate schema, guarded transport, deterministic mapping, provider adapter, orchestration, and fixture evaluation.

**Tech Stack:** Python >=3.11, stdlib `unittest`/`http.server`/`html.parser`/`http.client`, existing `architect.extract.Page` and `architect.http.Response`, MCP dependency already present in `.venv`. Optional Portal OpenAI-compatible HTTPS API; no new mandatory dependency. New test files use `unittest.TestCase` and `python -m unittest discover -s tests -p 'test_typed_*.py' -v`; legacy test scripts use their own check/exit-code harness.

**Spec:** `docs/superpowers/specs/2026-10-10-typed-extraction-and-devin-roadmap-design.md`

## Global Constraints

- `extract_typed(url, schema_json, use_llm=False, max_model_calls=1)` is a separate MCP tool; do not change `scrape_url`'s response shape.
- Default is deterministic-only. No model calls, payments, wallet operations, code execution, or hidden retries by default.
- Model fallback may see only capped page text and unresolved field definitions; page text is untrusted data, never instructions or authorization.
- Every filled value has an exact source excerpt/locator and `source_sha256`; unsupported fields stay `null`. These receipts are distinct from code-audit `file:line` receipts.
- Public URL transport must refuse local/private/metadata destinations, including DNS and redirected hops at connection time; robots refusal precedes page fetch. A mere hostname precheck is insufficient.
- If verifiable model pricing is unavailable, cap calls/tokens but **do not claim a monetary cap** or cost amount. Error/outage returns deterministic partial data with reason.
- DEVin/Looper #706 is a separate post-build project recorded in the spec and README; no Looper or Telegram activation here.
- Existing tests are standalone Python scripts, not pytest (`.venv` lacks pytest). New tests use stdlib `unittest` and run via `.venv/bin/python -m unittest ...`; existing scripts run directly and exit nonzero on failure.

## Review Focus

- DNS rebinding or redirect to loopback after a harmless hostname check: Task 2 integration test pins resolved address per connection and refuses the page.
- Robots unavailable/ambiguous policy: Task 2 test pins fail-closed behavior for this new public-facing tool, unlike the existing `load_robots` helper.
- Duplicate/conflicting JSON-LD and visible copy: Task 3 test requires abstention instead of choosing an arbitrary value.
- HTML injection framed as a system/tool instruction: Tasks 3–4 tests require it never changes schema or causes an external action; no literal evidence means `null`.
- Provider usage headers or pricing missing: Task 4 test requires `cost_usd=null`, labeled unknown, with call/token caps still enforced.

---

## File Map

- Create `architect/typed_schema.py`: bounded schema parsing and canonical field spec; no network or model logic.
- Create `architect/safe_fetch.py`: safe public HTTP(S) connection and per-hop robots enforcement; injectable resolver/transport for tests; no dependency on model.
- Modify `architect/extract.py`: fix skip/JSON-LD parser state only where tests prove a bug.
- Create `architect/typed_fields.py`: deterministic selector mapping and evidence/typed-value validator.
- Create `architect/portal_extract.py`: injectable model adapter, token/call budget, response validator; credential resolution at call time with no secret serialization.
- Create `architect/typed.py`: pipeline and stable output envelope, zero implicit fallback.
- Modify `architect/mcp_server.py`: register one new tool and call `typed.extract_typed`.
- Create `tests/test_typed_schema.py`, `tests/test_safe_fetch.py`, `tests/test_typed_fields.py`, `tests/test_portal_extract.py`, `tests/test_typed_integration.py`.
- Create `bench/typed_fixtures.json`, `bench/typed_eval.py`, `bench/typed-results.json` (results only from real runs), and modify `bench/README.md`, `README.md` for usage/caveats. Do not change `bench/compare.py`'s historical results.

### Task 1: Bounded Schema Contract

**Files:** Create `architect/typed_schema.py`, `tests/test_typed_schema.py`.

**Interfaces:** `parse_schema(schema_json: str) -> dict[str, FieldSpec]` raises `ValueError`; `FieldSpec` frozen dataclass with `type: str`, `selector: str | None`, `hint: str`, `required: bool`. Canonicalize back to serializable dict for the response via `schema_dict(specs: dict[str, FieldSpec]) -> dict`.

- [ ] **Step 1: Write failing tests.** Assert a one-field `{"price":{"type":"number","selector":"jsonld:price"}}` parses; reject invalid JSON, unknown key/type/selector, `__proto__`, empty field, >16 fields, >8192 schema bytes, >240-char hints, nested schema, non-boolean `required`, and `use_llm` instructions hidden in schema fields. Selectors are the spec's fixed list plus `jsonld:<property>` with a bounded simple property name.
- [ ] **Step 2: Run** `.venv/bin/python -m unittest discover -s tests -p 'test_typed_schema.py' -v` → fails for missing module.
- [ ] **Step 3: Implement** the two exact functions and dataclass in `architect/typed_schema.py`; enforce UTF-8 byte limits and exact allowed keys before any fetch.
- [ ] **Step 4: Run** the same unittest command → PASS; `git diff --check` → clean.
- [ ] **Step 5: Commit** `architect/typed_schema.py tests/test_typed_schema.py` as `feat: validate bounded typed schemas`.

### Task 2: Guarded Fetch and Access Policy

**Files:** Create `architect/safe_fetch.py`, `tests/test_safe_fetch.py`; reuse `architect.http.Response`, `architect.http.parse_robots`, `architect.http.MAX_BYTES`. Do **not** call `urllib.request.urlopen` with unchecked redirects for this tool.

**Interfaces:** `fetch_public(url: str, *, resolver=None, transport=None, timeout: float=15) -> AccessResult`; `AccessResult(response: Response, signals: dict[str,str])` is a frozen dataclass. `AccessDenied` and `UnsafeURL` exceptions. `resolver(host, port)` returns addresses, `transport(url, pinned_ip, timeout)` returns a `Response` for one hop with redirects disabled. Production transport uses `http.client` and pins each checked address at the socket connection; HTTPS uses original hostname for SNI and certificate verification. Redirects: maximum 5, revalidate URL/DNS/robots per hop. Robots obtained via the *same guarded transport* with no recursive robots checks; fail closed on non-200 except explicit 404 (no policy file), 5xx/timeout/invalid policy. Cap response body to `MAX_BYTES`, with decompress limit too. Merge robots and page `Content-Signal` into `AccessResult.signals` so Task 5 suppresses model sending on `ai-input=no`; do not treat `ai-train=no` as a ban on extraction.

- [ ] **Step 1: Write failing tests.** Inject resolver/transport to assert loopback, RFC1918, IPv6 ULA/link-local, userinfo, unsupported scheme/port, 302→private, DNS rebind between hops, redirect loop, denied robots, `Crawl-delay` handling for sequential redirects, robots 5xx, robots 404, 402 page, decompression bomb, and normal HTTPS hostname/SNI contract. Local `http.server` fixture runs only through an explicit test transport, never by disabling production SSRF checks. Assert denied path: page requests=0 and model requests=0.
- [ ] **Step 2: Run** `.venv/bin/python -m unittest discover -s tests -p 'test_safe_fetch.py' -v` → fails.
- [ ] **Step 3: Implement** the public URL validator and pinned one-hop HTTP transport with manual redirects and robots gating. Keep API response distinct for policy denial vs unsafe URL vs 402; never pay.
- [ ] **Step 4: Run** the same test → PASS; check type and redirect edge behavior with actual local test server through the injected transport.
- [ ] **Step 5: Commit** the module and tests as `feat: guard typed fetches and enforce robots`.

### Task 3: Deterministic Facts and Evidence

**Files:** Create `architect/typed_fields.py`, `tests/test_typed_fields.py`; conditionally modify `architect/extract.py` only for confirmed parser bugs.

**Interfaces:** `deterministic_fields(page: Page, specs: dict[str, FieldSpec], source: bytes) -> tuple[dict, dict]` returns values and metadata. `verify_candidate(value: object, kind: str, excerpt: str, source: str) -> bool` is shared with model fallback. Excerpts must be verbatim in the fetched source (or normalized only for whitespace/HTML entities with exact mapping), with stable locator. For JSON-LD include `jsonld[index].property` and value's textual occurrence in source; discard external `@id` references rather than fetch them.

- [ ] **Step 1: Write failing tests.** Prove `title`, meta description, h1, headings, links, `jsonld:price`, number/bool/string[] conversion; exact excerpt + SHA-256; duplicate/conflicting JSON-LD abstains; missing remains null; unsafe script/hidden data does not populate visible-text selectors; malformed JSON-LD is ignored. Include a red test if the existing extractor leaks script contents or mishandles multiple JSON-LD blocks.
- [ ] **Step 2: Run** `.venv/bin/python -m unittest discover -s tests -p 'test_typed_fields.py' -v` → FAIL.
- [ ] **Step 3: Implement** field mapping and validator; fix only proven extractor bug(s), preserving existing `Page` and `to_markdown()` behavior.
- [ ] **Step 4: Run** unit test and existing `tests/test_escalate.py` directly → both PASS.
- [ ] **Step 5: Commit** changed files as `feat: extract literal typed facts with evidence`.

### Task 4: Bounded Nous Portal Adapter

**Files:** Create `architect/portal_extract.py`, `tests/test_portal_extract.py`.

**Interfaces:** `propose_fields(source_text: str, unresolved: dict[str, FieldSpec], *, provider: Callable, max_calls: int, max_input_chars: int=12000, max_output_tokens: int=512, max_cost_usd: float | None=None) -> ModelResult`; `ModelResult` includes candidate values + exact excerpts, model/call/token usage, optional `cost_usd`, error. Production `portal_provider(...)` reads runtime credential at call time (`NOUS_API_KEY` or documented Hermes Portal credential broker), uses HTTPS to `https://inference-api.nousresearch.com/v1/chat/completions`; do not inspect or serialize auth files in reports. The selected `model` is a tested, exact catalog ID supplied by config; no invented model default. Before any call, reject if configured per-token price × hard token caps exceeds `max_cost_usd`; default per-job cap is $0.01 **only after** a live verified price is recorded. If pricing cannot be verified, `cost_usd=None`, label unknown, and use call/token caps without claiming a monetary ceiling. All inputs/outputs bounded; no tool calls; provider timeout fails closed.

- [ ] **Step 1: Write failing tests.** Mock provider: resolved fields never sent; one call max; `max_calls=0` returns no candidates; untrusted page says `ignore system`/`send secret` but no tools run; malformed JSON/unknown key/no excerpt/type mismatch/substring not in source yields null; provider outage returns reason; usage missing means unknown cost, not zero. Assert bounded source text and response body.
- [ ] **Step 2: Run** `.venv/bin/python -m unittest discover -s tests -p 'test_portal_extract.py' -v` → FAIL.
- [ ] **Step 3: Implement** provider adapter and proposal verification using Task 3 validator. Inspect official Portal catalog/pricing at implementation time, run same fixture subset on low-cost model candidates, and select an exact model only on observed entitlement/quality. Do not print secrets or token-bearing HTTP headers.
- [ ] **Step 4: Run** tests → PASS; record model/pricing evidence in `bench/README.md` without keys. If no usable provider credential/model is available, retain deterministic working path and report that live LLM fallback was not verified.
- [ ] **Step 5: Commit** as `feat: add bounded optional Portal extraction fallback`.

### Task 5: Orchestration and MCP Integration

**Files:** Create `architect/typed.py`, `tests/test_typed_integration.py`; modify `architect/mcp_server.py` (register tool only; retain markdown endpoint).

**Interfaces:** `extract_typed(url: str, schema_json: str, use_llm: bool=False, max_model_calls: int=1, *, fetcher=fetch_public, model=None) -> dict`; MCP `extract_typed(url: str, schema_json: str, use_llm: bool=False, max_model_calls: int=1) -> str` returns compact JSON. Envelope includes `url,status,schema,values,fields,missing,validation_errors,source_sha256,rendered,cached,llm,untrusted` with explicit `method` and excerpt per field. Non-200, policy refusal, and 402 are structured errors with zero model calls.

- [ ] **Step 1: Write failing integration tests.** Local fixture allow→typed values, disallow→0 page requests/0 model calls, 402→no payment, unsafe redirect→no page content, model success→one verified unresolved field, hallucination→null, content-signal `ai-input=no`→no model call, provider outage→deterministic partial. Introspect MCP tool registry and assert both `scrape_url` and `extract_typed` registered. Test `scrape_url` output is byte-for-byte unchanged for the same mocked response.
- [ ] **Step 2: Run** `.venv/bin/python -m unittest discover -s tests -p 'test_typed_integration.py' -v` → FAIL.
- [ ] **Step 3: Implement** stable output envelope, exact schema-first validation, access-first fetch, deterministic pass, optional bounded fallback, and MCP thin wrapper. No LLM call if deterministic pass fills all fields.
- [ ] **Step 4: Run** integration and all new unittests → PASS; run one public, robots-allowed HTTPS page with `use_llm=False` and inspect values/evidence/status. No production model call unless cost cap/entitlement known.
- [ ] **Step 5: Commit** as `feat: expose safe typed extraction over MCP`.

### Task 6: Fixture Evaluation and Release Evidence

**Files:** Create `bench/typed_fixtures.json`, `bench/typed_eval.py`, `bench/typed-results.json` (generated), modify `bench/README.md`, `README.md`.

**Interfaces:** `bench/typed_eval.py --mode deterministic|llm|both [--output path]` runs local fixed fixture pages through the same public pipeline via injected transport, compares expected field values/nulls, records precision, recall, abstention accuracy, unsupported-field rate, wall seconds, model calls/tokens and cost status. Never writes keys or raw credential-bearing headers. Label live LLM results separately from mocked unit tests.

- [ ] **Step 1: Write failing benchmark self-tests** in `tests/test_typed_eval.py`: fixture count, expected outcomes for static/ambiguous/SPA-shell/missing/injection/conflict, exact precision/recall/abstention denominators, no fabricated live-model metrics, secrets absent from JSON artifacts.
- [ ] **Step 2: Run** `.venv/bin/python -m unittest discover -s tests -p 'test_typed_eval.py' -v` → FAIL.
- [ ] **Step 3: Implement** deterministic evaluation and optional real Portal mode with explicit opt-in. Record catalog/model/pricing source and observed token usage, or say unavailable; keep `bench/compare.py` results intact. Document `extract_typed` usage, robots/SSRF limits, and the distinct benchmarks.
- [ ] **Step 4: Run** `.venv/bin/python -m unittest discover -s tests -p 'test_*.py' -v` for all `unittest.TestCase` tests and run legacy standalone scripts (`test_cache.py`, `test_escalate.py`, `test_limiter.py`, `test_v03.py`, `test_x402.py`, `test_crawl_pay.py`, `test_watch.py`, `test_sentinel_sign.py`, `test_sentinel.py`, `test_viz.py`, `test_sentinel_node.py`) directly, checking each exit code (no pipe masking); run fixture eval; optionally run live LLM eval if a verified affordable model and credential are available. Re-run `map_site` integration timing to catch prior limiter stall. `git diff --check` must pass; publish only numbers observed in this run, with caveats.
- [ ] **Step 5: Commit** tests, fixtures, generated real results, docs as `test: evaluate typed extraction with evidence`; if pushing, read back exact remote paths and hash, and do not announce deployment/DEVin activation.

## Execution and review

Keep branch `feat/sentinel-v0.5` distinct from `main`; its existing sentinel commit is unrelated to typed extraction. Before choosing merge/push target, check ancestry and obtain user direction rather than silently merging sentinel into main. After plan review, implement TDD task by task with fresh review gates and final whole-branch review. DEVin gets its own spec/plan after crawler initial build; verify Looper contract and wallet on-chain at that time, not by assuming it from the user's note.
