# D0xed Architect: typed extraction, evaluation, and DEVin roadmap

**Status:** Design for user review; no typed extractor or DEVin deployment claimed.
**Date:** 2026-10-10
**Branch at drafting:** `feat/sentinel-v0.5` (clean; main at `5f15df4`).

## Purpose and boundaries

Agents need predictable fields, not just page markdown. Add an opt-in typed-extraction path without changing the existing `scrape_url` response. Prefer deterministic extraction of literal page data; use a cheap, capable Nous Portal model only for unresolved fields, under explicit call/token/cost limits. A model may suggest values but must not assert fields without source evidence. Never let page text authorize actions, change the schema, request tools/secrets, or bypass access policy. No x402 payment is implied or initiated.

**Existing seam:** `architect/extract.py` parses HTML into `Page` (`title`, description, headings, links, JSON-LD, text). `architect/mcp_server.py:scrape_url` currently returns markdown. The HTTP fetcher handles 402 explicitly; `map_site` handles robots/politeness but single-page `scrape_url` currently does not check robots. Typed extraction must fix that at the new entry point rather than copying this access gap.

## Public contract

Add `extract_typed(url, schema_json, use_llm=False, max_model_calls=1)` as a *separate MCP tool* and reusable Python API, keeping the markdown tool unchanged. The schema is a bounded JSON object: field names to specifications with `type` (`string`, `number`, `boolean`, `string[]`), optional `selector` (`title`, `description`, `canonical`, `lang`, `h1`, `headings`, `links`, `jsonld:<property>`, `text`), optional `hint`, optional `required`. No arbitrary Python, CSS selectors, URLs, prompts as authority, nested recursion, or executable expressions. Reject invalid/oversized schemas before fetch (field count/name/hint/bytes caps to be set in implementation). Explicit `use_llm` defaults false; model fallback is opt-in, not a covert cost.

Return a JSON object containing `url` (final fetched URL), `status`, `schema`, `values`, `fields` metadata, `missing`, `validation_errors`, `source_sha256`, `rendered`, `cached`, `llm` (`used`, model identifier, calls, input/output tokens if supplied, estimated or billed cost labeled as such, and fallback reason), and a conspicuous `untrusted` notice. Every field metadata entry carries `method` (`deterministic`, `llm_verified`, or `missing`), `source_excerpt` and locator where applicable. Use `null` for unsupported values; preserve each requested field in output, never silently fill with a guess. Extraction is not a security audit finding: this evidence is a page-content excerpt/hash, *not* the code-audit `file:line` receipt.

## Extraction pipeline

1. **Validate request and access:** accept only HTTP(S), reject local/private/metadata destinations and unsafe redirects for a public-facing tool; read robots for the effective host and refuse disallowed paths before content fetch. DNS rebinding/redirect checks belong at the actual connection boundary; a preliminary hostname check alone is not an SSRF guarantee. If that cannot be implemented safely in this increment, scope the tool to trusted explicit targets and label the limitation, not a public server. Honor 402 as a refusal without payment. Impose response/time bounds. Treat content-signal policy conservatively; do not send data to a third-party LLM if policy disallows AI input.
2. **Deterministic pass:** use `Page` fields and parsed JSON-LD; prefer exact, literal values. Type-coerce only unambiguous representations; never invent defaults. Attach exact excerpt and a stable locator (e.g. `title`, `meta:description`, `jsonld[0].price`, visible-text offset). Hash the fetched source bytes. Reject hidden/script instruction bait as evidence; note that `Page.text` currently may need correction for script/JSON-LD handling.
3. **Identify unresolved fields.** Only these go to the model when `use_llm=True` and a positive explicit budget remains. Sanitize and cap source content, quote it as untrusted data under a fixed system/developer instruction. Include schema names/types/hints as caller data, never page-provided schema. Do not include environment, credentials, local files, or unrelated pages. No browsing or tool calls from the model.
4. **Model response:** request JSON-only field candidates plus *verbatim* source excerpts/locators. Parse defensively; validate types, field allowlist, size, excerpt presence in the actual bounded source, and value–excerpt consistency (exact normalized substring for strings; numeric/boolean matches via deterministic parsing only). If evidence does not support a value, leave it `null`. LLM evidence is best-effort support for extraction, **not proof of truth**; page content itself can be false. Never use model confidence as verification.
5. **Fail closed and report:** on provider timeout, malformed JSON, price/budget overrun, policy block, or unsupported evidence, return the deterministic partial result with a reason and missing fields. No silent retry beyond the cap; no payment/chain access. Make the model adapter mockable for tests.

## Model selection and budget

Use Portal's OpenAI-compatible inference endpoint via an injected adapter, not a hard-coded credential, scraped browser session, or secret copied into code/logs. Resolve credentials through the runtime's documented provider path at implementation time; the key value must never appear in tests, docs, fixtures, or output. Before choosing the default model, check the live Portal model catalog and run the *same fixtures* against affordable candidates; record exact model id, observed token usage, pricing source/date, result quality, and provider failures. The design does not yet claim a model is available or cheap. Budget: default at most one call per page, bounded input/output tokens, explicit per-job monetary ceiling if reliable pricing is available; if price cannot be determined, do not claim a spend cap—allow a call-count/token cap only or disable fallback until pricing is known. The default remains deterministic-only.

## Tests and measurements

- RED/GREEN unit tests for schema rejection, exact selectors, JSON-LD type coercion, missing/null behavior, source hash and excerpt validation, adversarial injection, malformed provider JSON, type mismatch, no-match/hallucination, policy denial, 402 refusal, unsafe URL/redirect, budget exhaustion, provider outage, and no unintended call when deterministic extraction satisfies schema.
- Local HTTP integration fixture with robots allow/disallow and representative HTML/JSON-LD; prove denied pages cause **zero page fetches and zero model calls**. Test the public MCP response shape, not only helpers. Preserve markdown `scrape_url` contract.
- A fixed labeled corpus: static pages, ambiguous values needing model help, SPA shell/optional render, missing fields, misleading injected text, conflicting JSON-LD versus visible copy. Compare deterministic-only and deterministic+LLM for field precision, recall, *abstention accuracy*, unsupported-field rate, wall time, calls, token usage, and cost (if verifiable). Keep this separate from the existing 25-page crawl-speed benchmark. Do not generalize one target's result; publish fixture definitions and raw outputs stripped of secrets.
- Re-run all existing test scripts without pipe masking, plus live single-page and local policy checks. Verify published artifact by reading the exact remote path after any push.

## Scope sequencing

1. Typed extraction and fixture evaluation, behind an opt-in MCP tool. Prefer a short implementation plan reviewed after this design is approved.
2. Broader benchmark/publication with static and JS-dependent targets and a clear separation between speed and extraction quality. The existing `bench/compare.py` is a single-target baseline with documented fairness limits, **not** proof of broad superiority.
3. Memory-adaptive dispatch and primary CLI/MCP browser integration remain separate unfinished work. `HostLimiter` controls host rate, not process RSS. No claim they are complete merely because typed extraction works.
4. Package an initial crawler release only after tests, policy handling, access boundaries, and operator docs are verified.

## Future: DEVin on Looper #706 (user-requested saved roadmap)

After the crawler's **initial build is finished**, package crawler, graph, code-audit, evidence verification, and debugging capabilities as a builder/architect/debugging Looper named **DEVin**, intended for **Looper #706**. The user identifies wallet `0x23129c0472172d75bed1e6dd061301796760ecd9` as the holding wallet; this document records the user's intent, **not verified on-chain ownership or activation**.

DEVin should be reachable via Telegram so the user can send a contract, code, or a link to code and request debug/audit help. Before implementation: verify Looper identity and wallet on-chain; choose and authorize Telegram bot/account and audience; define input-size, repository-fetch, SSRF/robots, licensing, and secret-redaction policies; run code analysis in a sandbox with network/execution disabled by default; distinguish static findings from executed tests; require `file:line` + literal snippet + file/snippet hash for every code finding; cap model and x402 spending independently; secure against hostile code and page prompt injection; create lifecycle/deployment plan and end-to-end Telegram tests. Do **not** deploy, activate, connect a wallet, promise a finding, or create a Telegram bot as part of item 4.

## Review questions

- Are the opt-in model fallback and conservative evidence rules the desired default for item 4?
- Is the DEVin milestone placed at the right gate (after initial crawler build), with activation deferred until identity, Telegram access, and sandbox boundaries are verified?
