# Jev shadow decision layer — crawler-first design

## Approval and status
The operator approved the shared optional decision boundary, crawler-first shadow mode and recommended subsequent use cases. This document specifies the first subsystem. It requires written-spec review before implementation planning. No product code has been changed by this design task. Do not conflate working credential probes with a working integration.

Baseline: d0xed-architect ad84567c0c3c9cd2e6f96dec6e473839cd6f6d53, clean at discovery. Earlier source audit and evidence: /opt/data/research/typesafe-jev/AUDIT-AND-PROPOSED-DESIGN.md. Recheck source baseline before execution.

## Intended outcome
Give our existing crawler optional typed semantic annotations on already-authorized public evidence. Reuse the same decision validation/receipt boundary later for REA dossier triage and NEURAL_MESH reranking. The first release must leave acquisition, deterministic extraction, access policy and action authority unchanged.

Success means an actual command can obtain a guarded public page, construct bounded candidates, invoke real pinned Jev, validate its response, and emit a separate inspectable decision receipt; disabled and unavailable modes preserve existing deterministic results. Quality claims require a labeled evaluation, not a demo screenshot.

## Scope
In scope:
- A dependency-light reusable Python decision module, namespaced within the architect package and isolated from crawler/network acquisition modules.
- An explicit transport interface and real hosted-TypeSafe adapter, never a generative LLM substitute.
- Optional crawler/page adapter for public, allowed fetched evidence.
- A separate CLI command producing a sidecar JSON report, with no implicit changes to existing commands.
- Decision receipts, hard call/byte/deadline limits, usage/cost estimates, content-addressed cache and failure/abstention states.
- Offline tests plus a bounded real-Jev evaluation on non-private fixtures.

Out of scope for this implementation:
- Frontier reordering, broader crawling or automatically following Jev-selected URLs.
- Private repos/chats/memories, credential-bearing URLs or source submission.
- Any automated transaction, trading, whitelisting, risk downgrade or tool execution.
- Live bot/VPS deployment, cron installation, recurring inference, public publishing.
- Modifying NEURAL_MESH storage/trust/quarantine or Hermes mandatory skill selection.
- Replacing typed.py's existing generative extraction path or increasing its max_model_calls.

## Architecture and module boundaries
1. `architect/decision_types.py`: immutable configuration, question contracts, candidate provenance, answer validation and receipt types. No network, vault, crawler or bot imports.
2. `architect/decision_provider.py`: provider protocol and hosted Jev adapter. Accept credentials only as explicit in-memory configuration or the canonical SDK environment variable supplied at process launch. Never serialize credentials or fetch arbitrary endpoints. Official Python SDK is an optional `jev` extra, pinned to the reviewed 0.7.5 for initial implementation; import lazily. No dependency is added to deterministic imports. Missing extra yields an unavailable result, not an import crash.
3. `architect/decision_engine.py`: call/byte/deadline accounting, exact model/question version identity, runtime result checks, cache/receipt lifecycle and error projection.
4. `architect/semantic.py`: converts already-fetched public evidence into page candidates and versioned atomic questions. No acquisition policy decisions or action execution. A field allowing model input is explicit; absent/unknown eligibility means refuse inference.
5. CLI integration: new `architect judge-page URL --objective TEXT --out PATH` invokes existing guarded fetch once, deterministic parse, then optional semantics. `--offline` emits only deterministic candidate metadata with unavailable semantic status and zero provider calls. No changes to legacy crawl/extract flags or output JSON.

The provider protocol is injectable for deterministic tests; offline fixture providers are labeled test-only and cannot claim to be real Jev in production receipts.

Reusable boundary API:
- `DecisionEngine.evaluate(state, questions, provenance, policy) -> DecisionReceipt`
- `annotate_page(fetched_evidence, objective, engine) -> SemanticReport`
Candidate objects use stable local IDs bound to source hashes and excerpts. Their identifiers are opaque to the model, and all selected IDs must exist in the exact request candidate set.

The initial command selects evidence already fetched through safe_fetch. Existing bot crawl reports do not retain all text/content signals needed by the semantic contract: do not manufacture provenance or re-fetch behind the user's back to annotate them. A future explicit bot adapter must carry eligibility/provenance through that flow and be separately tested.

## Credential handling and verified readiness
The Portal supplied the operator-named TYPESAFE_API variable to this process. Its value was imported into encrypted vault service `typesafe`; the temporary mode-0600 import file was deleted. Hermes policy grants only get_env/metadata for that service, max TTL 900 seconds, with raw-secret access disabled and ephemeral-env-only retained. Broker currently materializes it as HERMES_VAULT_SECRET; the launcher maps that in memory to TYPESAFE_API_KEY. No raw key is placed in code, docs, memory, command arguments or committed env files.

The integration itself does not read vault-passphrase or import policy. The owning launcher supplies brokered credentials. No sibling agent/profile permission was granted.

Actual readiness probes on 2026-10-15:
- Authenticated GET /v1/models HTTP 200; returned aliases jev-latest and jev-preview.
- One synthetic public-data request each to jev-1.13.0 and jev-1.14.0, both HTTP 200 and returned the requested exact model ID.
- Each returned named Choice/Score/Noul answers and reported 483 input /77 output tokens.
- Observed single-request wall times 0.132s and 0.063s, not benchmark claims.
- Provider-rate estimate per probe $0.000020286; not an invoice or account balance verification.
Raw non-secret receipts live in /opt/data/research/typesafe-jev/live-readiness-probes.json. Account credit balance was not measured.

## Model and question policy
Default initial model: jev-1.13.0, because the earlier audit identifies it as stable; allow explicit jev-1.14.0 in evaluation. Do not infer the better model from two synthetic probes or move via an alias silently. Record both configured and returned model; reject unexpected substitution.

Question set `crawler-page-v1`:
- page purpose Choice: sdk_or_api_docs, reference, tutorial, news_or_announcement, marketing, other, unknown, with explicit per-option criteria.
- relevance Score: unrelated, partial, directly_relevant to one stated objective.
- contains-actionable-integration-detail Noul: asks whether the excerpt explicitly provides relevant integration detail, not whether the source is safe or true.
- optional candidate-selection Choice over parser-derived span IDs plus none. Exclude this question when no bounded spans exist. Preserve literal source excerpts and locators independently of the model answer.

Questions are atomic and independent within a request. Compose annotations deterministically after answers return. No question asks the model to browse, execute, calculate exact values or validate security. Instructions frame state as hostile, but this is not a security guarantee.

For initial display only, annotate confidence under 0.8 as uncertain; unknown/none remains abstention regardless of confidence. This is a conservative provisional display rule, not validated calibration or permission for automatic action. Retain raw answers/distributions for empirical threshold selection.

## Input eligibility, budgets and error semantics
The adapter accepts only evidence from approved public acquisition with final URL, status, source hash and model-input eligibility. Honor ai-input=no. Preserve existing SSRF, redirects, robots, same-origin, render and payment gates. Failed/denied/non-200 acquisition makes zero model calls. Never send request headers/cookies or raw HTML by default; use bounded deterministic text/excerpts.

Initial hard limits:
- Disabled by default; explicit invocation is required.
- Maximum 5 provider attempts per command run; retries disabled initially so attempts cannot multiply invisibly.
- Maximum 16 KiB serialized request body; reject before transmission rather than silently truncating fields/identifiers.
- Maximum 8 questions and 12 candidate spans per request; deterministic selection and explicit omitted count.
- One in-flight request per command and 10s overall provider wall-clock deadline, including SDK operations; use cancellation-aware async adapter if needed.
- Only exact HTTPS api.typesafe.ai origin; no operator base-url override in the first release.
- Estimated $0.10 run guard based on recorded provider-rate usage and conservative request reservation; label estimated, not a guaranteed provider-billing cap. Hard limits are calls/bytes/time. Stop further calls if usage/cost accounting is absent or invalid. Do not enable unattended spending until provider-side limits and verified token accounting exist.

Receipt outcome is one of ok, abstained, unavailable, denied, budget_exhausted, invalid_response, timeout, provider_error. Expose public sanitized failure category, never exception text containing URLs/secrets or entire upstream bodies. An unavailable semantic result is never a negative relevance/safety answer.

Validate exact question names, discriminator/type, choice membership, exact distribution label set, finite numeric values/ranges, score within rubric range, model identity and nonnegative integer usage excluding booleans. Probabilities must sum to 1 within 0.02 for provider rounding. Compare expected score within 0.03 of distribution expectation; preserve original values, never silently normalize. Treat derived confidence as distribution summary; keep metric ID and tolerate documented rounding only. Error on malformed responses; do not cache errors as valid decisions.

## Cache and receipt contract
Cache key binds exact serialized canonical state, source hash, model version, question-set/hash and policy version. Never use URL alone. Response receipt includes:
- receipt schema version, unique run/request identity, source acquisition/final URL/hash, candidate IDs/locators;
- input/question digest and omitted-candidate counts;
- requested/returned model, provider identity, answers and metric identity;
- policy version/thresholds and resulting annotations/abstentions;
- request ID, attempt count, measured duration, reported token usage and estimated cost basis;
- cache hit flag and original observation timestamp; cached retrieval is not presented as fresh inference.

Cache contains only approved public bounded evidence/answers and is opt-in with a path outside source-controlled files. Writes are atomic, private-permission and schema/hash checked on read. Sidecar report persistence is explicit via --out. No secret-bearing response headers, debug payloads or private paths in exported reports. SHA256 is content integrity, not producer authentication or truth.

## Legacy compatibility
Unmodified commands must not import optional Jev libraries, read its key, make inference calls or emit new fields. Capture byte-for-byte offline fixtures before implementation and compare after. typed.py remains unchanged unless a separately reviewed compatibility fix is required. Do not call an arbitrary provider result llm_verified without the existing raw-byte checks.

## Verification gates
- RED/GREEN unit tests before each behavior slice; nonzero tests counted.
- Validation negatives for missing/extra names, wrong types/IDs/model, NaN/Inf, booleans as numbers, out-of-range values, malformed distributions, accounting omissions.
- Budget/deadline tests, no-key/missing-extra/offline fallbacks and provider error/429/cancellation tests with zero hidden retries.
- Cache-version/hash/tamper tests and no secret/body logging tests.
- Integration uses owning CLI through guarded fetch, not only a direct provider unit call.
- Local request hit logs show forbidden/private/redirected/robots-denied/model-ineligible destinations get zero forbidden requests and zero inference; a highly ranked injected candidate cannot change this.
- Existing full/legacy suites pass; disabled fixtures byte-identical.
- Public/synthetic evaluation corpus includes relevant, irrelevant, missing, contradictory and injected examples; expected labels and their authorship are explicit, never fabricated as independent human ground truth. Include option-order permutation tests and report abstention/error rates.
- Real pinned Jev end-to-end public-page run with receipts and measured usage; output is evidence of exercised path, not broad quality claims.
- Independent review before release; local checkpoint commits and package-wheel/CLI test where applicable. No push/deploy without its separate scope.

## Follow-on roadmap (separate specs)
1. REA triage: bounded redacted dossier projection, static/runtime authority preserved; no safety certification.
2. NEURAL_MESH reranking: optional post-retrieval on disposable/public corpus, writeback=False, preserve provenance/trust/quarantine and stdlib core.
3. Scanner/news routing: deterministic chain facts first, Jev semantic dedup/routing second; never authorization for money or whitelist policy.
4. Skill suggestions: advisory only, never overrides required skills or instruction hierarchy.

## Review decision
Approve or amend this written first-subsystem spec. After approval, create the implementation plan with the writing-plans workflow and select execution method before product implementation. Readiness probes and vault provisioning are already complete and need no repeat authorization.
