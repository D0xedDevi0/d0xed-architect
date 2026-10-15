# Jev Shadow Decision Layer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-driven-development (recommended) or executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship an optional public-page Jev annotation command with validated receipts, bounded spending and unchanged legacy behavior.

**Architecture:** A pure validation/receipt boundary sits between a lazy hosted-Jev provider and the public-page adapter. Acquisition and policy remain deterministic. A new command emits shadow-only sidecar annotations; existing crawl/extract/bot flows remain unchanged.

**Tech Stack:** Python >=3.11, stdlib dataclasses/json/hashlib/asyncio/decimal/unittest, optional typesafe-sdk==0.7.5, existing safe_fetch/extract and argparse.

**Spec:** `docs/superpowers/specs/2026-10-15-jev-shadow-decision-layer-design.md` (approved by operator).

## Global Constraints
- Default `jev-1.13.0`; explicit evaluation alternative `jev-1.14.0`; no aliases/substitution.
- Maximum 5 provider attempts per run; SDK retries 0; one request in flight.
- Maximum 16 KiB serialized request body, 8 questions and 12 candidate spans.
- Overall provider deadline 10s, including SDK operations; cancellable asynchronous implementation.
- Only `https://api.typesafe.ai`; ambient TYPESAFE_BASE_URL/default-model settings cannot override explicit options. Disable redirects in the injected HTTP client.
- Estimated $0.10 run guard; published input rate $0.042/M, output free; never call the estimate a guaranteed billing ceiling.
- Distribution sum tolerance 0.02; expected-score consistency tolerance 0.03; finite values only; booleans are not numeric values.
- Provisional confidence display floor 0.8; unknown/none means abstain independently of confidence.
- No live bot/VPS changes, cron, recurring inference, private data, frontier reordering, trading, whitelist changes or risk downgrade.
- Credentials supplied in memory by the owning vault launcher. No vault implementation or passphrase access in product code. Canonical child env name TYPESAFE_API_KEY.
- Checkpoint explicit files only, effective git identity verified; local commits are not pushes/deployments.

## Review Focus
1. Host redirects can leak or redirect requests: provider must reject redirects; page wrapper must block cross-origin destinations before network I/O.
2. Model-input permission is absent on many pages: require explicit eligibility; operator attestation may establish missing eligibility but never override ai-input=no.
3. Parsed text contains HTML-decoded strings absent in original bytes: only literal byte-backed spans receive source locators; omission is explicit.
4. SDK cancellation/close can outlive the nominal timeout: test a hanging HTTP transport and prove no late successful receipt or extra attempt.
5. A cache entry may be validly hashed yet poisoned or symlinked: validation plus private-directory/file policy is required; hashes alone are not authority.

## File map and public contracts
Create:
- `architect/decision_types.py`: frozen policy/provenance/transport result/receipt dataclasses, canonical serialization, pure validation.
- `architect/decision_provider.py`: async provider protocol and optional official SDK adapter.
- `architect/decision_engine.py`: synchronous entry around bounded async evaluation, budgets and receipt composition.
- `architect/decision_cache.py`: opt-in private atomic cache with schema/key/digest checking.
- `architect/semantic.py`: eligible guarded acquisition, literal candidate extraction and page questions.
- `architect/judge_cli.py`: new command implementation and report serialization.
- `tests/test_decision_types.py`, `tests/test_decision_provider.py`, `tests/test_decision_engine.py`, `tests/test_decision_cache.py`, `tests/test_semantic.py`, `tests/test_judge_cli.py`, `tests/test_jev_compat.py`.
- `bench/jev_eval.py`, `bench/jev_fixtures.json`, `docs/JEV.md`.
Modify only `architect/cli.py` for lazy command registration and `pyproject.toml` for optional extra. Do not modify safe_fetch, typed.py, extractor, bot crawler or NEURAL_MESH for this subsystem.

Interface names owned by Task 1:
- `DecisionPolicy`: frozen dataclass containing model, question_set, policy_version, max_attempts=5, max_body_bytes=16384, max_questions=8, max_candidates=12, deadline_s=10.0, estimated_budget_usd='0.10', confidence_floor=0.8.
- `Provenance`: frozen dataclass with source_url, final_url, source_sha256, model_input_allowed, candidate list, omitted_candidates. Validate public credential-free origins and SHA256 format; no secret headers/raw HTML fields.
- `ProviderResult`: frozen dataclass with payload:dict and request_id:str|None.
- `DecisionReceipt`: frozen dataclass with schema_version, receipt_id, outcome, reason_code, provenance, requested_model, returned_model, question_set/hash, policy_version, answers, annotations, usage, attempts, duration_s, estimated_cost_usd, cost_basis, cache_hit, observed_at; `.to_dict()` exports an allowlisted JSON projection.
- `validate_response(payload:dict, questions:dict, expected_model:str) -> dict`: returns validated payload or raises `DecisionValidationError` with fixed public reason code.
- `canonical_json(value:object) -> bytes`: sorted keys, compact separators, ensure_ascii=True, allow_nan=False; the same bytes drive body limits/cache identity.

### Task 1: Pure contracts, validation and baseline fixtures
**Files:** create decision_types and test_decision_types/test_jev_compat; baseline evidence outside repo under `/opt/data/research/typesafe-jev/implementation/`.
**Consumes:** approved spec and existing extractor/typed fixtures.
**Produces:** exact interfaces listed above; baseline compatibility artifacts.

- [ ] Capture pre-change CLI help and deterministic fixture outputs outside repo; run `.venv/bin/python -m unittest discover -s tests -p 'test_extract_compat.py' -v` and record nonzero count. Record `architect/typed.py` digest and deterministic extraction JSON fixture with timing-free fields. Inventory legacy custom-script test runners, not just unittest discovery.
- [ ] Write `test_valid_choice_score_noul`, `test_unexpected_names_model_or_labels`, `test_bad_numeric_values`, `test_distribution_and_expected_score`, `test_receipt_export_redacts_unapproved_fields`. Assert sum deviations >0.02 fail, score expectation deviations >0.03 fail, confidence outside [0,1] fails, bool/NaN/Inf/negative usage fails, and extra answer names fail. A valid response includes the exact requested model and all requested answer types.
- [ ] Run `.venv/bin/python -m unittest discover -s tests -p 'test_decision_types.py' -v`; require observed RED from missing behavior, not an unrelated dependency failure.
- [ ] Implement frozen dataclasses, strict config validation and pure response validation. Validate Choice confidence against documented probability-derived metric with 0.02 rounding tolerance; Score uses ordinal-distance confidence with the same tolerance. Noul has no invented independent confidence. Validate Score legend and rubric keys. Preserve original values; never normalize silently.
- [ ] Run owning tests GREEN and existing extraction compatibility fixture tests. Verify imports of pure contracts do not import SDK or read credential env variables.
- [ ] Commit explicit contracts/tests and record SHA. No production key in fixtures; test credentials use clearly synthetic markers.

### Task 2: Real hosted SDK adapter with cancellation and credential isolation
**Files:** create decision_provider/test_decision_provider; modify pyproject optional dependencies.
**Consumes:** ProviderResult/DecisionPolicy from Task 1.
**Produces:** `AsyncDecisionProvider` protocol with `async ask(body:dict) -> ProviderResult`; `JevProvider(api_key:str|None=None)` implementing it. Fixed provider identity `typesafe-hosted`; test providers cannot impersonate it.

- [ ] Write `test_lazy_optional_import`, `test_missing_key_or_extra_unavailable`, `test_fixed_host_model_retry_and_no_redirect`, `test_logs_never_contain_body_or_key`, `test_cancel_hanging_transport`. Fake SDK/http transport captures construction/request options; assert explicit base URL/model, retry count 0 and no redirects even when ambient env attempts override them. Hanging request must cancel with zero subsequent attempts.
- [ ] Run `.venv/bin/python -m unittest discover -s tests -p 'test_decision_provider.py' -v` and preserve RED.
- [ ] Add `jev = ['typesafe-sdk==0.7.5']`; leave mandatory dependencies/all extras unchanged. Lazy-import SDK only inside async ask; use AsyncTypeSafeClient with an explicitly constructed httpx2 async client, follow_redirects=False and fixed base URL. Inspect installed signatures before coding, configure SDK debug off and ensure no payload logging enters root handlers. Extract request ID from supported raw-response API rather than inventing a field. If unavailable, retain null with a documented reason, not a fabricated ID.
- [ ] Install reviewed extra into a task-isolated environment after inspecting dependency resolution; do not alter platform-managed Hermes venv. Use brokered env only for later explicit live runs; no credentials needed for mocked SDK tests.
- [ ] Run owning tests GREEN, including actual cancellation-aware mocked network transport. Classify missing key/extra as unavailable, HTTP 429/other provider failures as sanitized provider_error; never return raw exception content.
- [ ] Commit adapter/extra/tests explicitly.

### Task 3: Engine, budget accounting, cache and auditable receipts
**Files:** create decision_engine/decision_cache and owning tests.
**Consumes:** Task 1 types; Task 2 async protocol.
**Produces:** `DecisionEngine(provider, policy, cache=None)`; `evaluate(state:dict, questions:dict, provenance:Provenance, policy:DecisionPolicy|None=None) -> DecisionReceipt`. `DecisionCache(root:Path).get(key:str) -> dict|None` and `.put(key:str, receipt:dict) -> None`.

- [ ] Write engine tests asserting 6th attempt is refused, byte length 16385 refused, 9 questions/13 candidates refused, eligibility false denied, unexpected model invalid_response, overall deadline timeout, no-key unavailable, and missing usage closes the run to subsequent calls. Cache hits spend no attempt and are marked cached with original observation time.
- [ ] Write cache tests for state/source/model/question/policy invalidation, modified bytes, valid hash but invalid response, symlink file/directory refusal, directories mode 0700/files 0600, atomic replace, and no caching of provider errors. Root must be explicit and outside repository; reject paths inside any detected source-controlled worktree.
- [ ] Run owning test modules RED.
- [ ] Implement engine without global credentials/state, lock one provider request in flight, and use asyncio timeout around ask plus cleanup. Call limit counts attempted provider transmissions even on failure. Estimate reservation as serialized bytes times $0.042/M (one estimated token per byte, explicitly not a proved tokenizer upper bound); reconcile with reported tokens after a response. Use Decimal, reject invalid/nonfinite policy values, stop if estimate guard cannot reserve the request or usage is absent. Include no exception/body text in public errors. Record cache trust limits.
- [ ] Implement cache key from canonical exact state/questions/provenance source hash/model/question_set/policy identity; use exclusive private temporary file, fsync and atomic replace. Revalidate cached payload and original identity before emitting fresh cached receipt. Do not claim content hashes prove authenticity.
- [ ] Run both suites GREEN; run Task 1/2 regressions and concurrent-call budget tests. Commit explicit modules/tests.

### Task 4: Public-page adapter and sidecar CLI
**Files:** create semantic/judge_cli and tests; lazy registration in cli.py.
**Consumes:** existing `safe_fetch.fetch_public() -> AccessResult`, `extract(..., typed=True) -> Page`, Task 3 engine.
**Produces:** `fetch_judgment_page(url:str) -> AccessResult`, `annotate_page(fetched_evidence:AccessResult, objective:str, engine:DecisionEngine, *, operator_allows_model_input:bool=False) -> dict`; `cmd_judge_page(args) -> int`.

- [ ] Write tests for ai-input=no, missing eligibility, non-200/402, inaccessible robots, private IP/DNS/redirect, cross-origin redirect, hidden DOM, nonliteral decoded spans, empty objective, omission counts, an injected URL selected by provider, and malformed candidate IDs. Every denied/model-ineligible case must record zero provider calls. An injected selection must never cause another fetch.
- [ ] CLI contract: `judge-page URL --objective TEXT --out PATH [--offline] [--allow-model-input] [--model {jev-1.13.0,jev-1.14.0}] [--cache-dir PATH]`; out/objective required. Explicit command is inference opt-in; offline always makes zero inference calls. `--allow-model-input` is explicit public-content attestation only when policy is silent; cannot override ai-input=no. Reject credential-bearing URLs and token-like query parameter values before fetch/export.
- [ ] Run owning tests RED. Use local HTTP hit-log harness through injected resolver/transport; test-only mapping to the harness must never weaken production public-IP rules.
- [ ] Implement same-origin transport wrapper passed to existing fetch_public: inspect every requested URL before delegating to safe_fetch._transport, including redirects/robots, and reject differing scheme/host/effective port before network I/O. Do not change existing cross-origin behavior globally. Keep public-IP pinning and robots enforcement in fetch_public intact.
- [ ] Build candidates from typed visible text_nodes, cap each excerpt at 512 UTF-8 bytes on character boundaries, retain only excerpts found literally in response.body, attach byte offsets/source hashes, cap at 12 and count omissions. Do not send raw HTML, cookies, headers, emails or private snippets; omit and count secret/PII-like spans using deterministic conservative filters. Whole-page state comprises bounded title/objective and approved candidate excerpts, with one per-page shared state.
- [ ] Build exact crawler-page-v1 Choice/Score/Noul plus optional explicit candidate Choice/none; unknown/none/low confidence never authorizes action. Engine returns a separate semantic report with deterministic candidate metadata intact on failure.
- [ ] CLI writes sidecar atomically mode0600; emits no raw upstream bodies. Exit codes 0 for ok/abstained/offline, 1 for provider unavailable/failure/timeout/budget/invalid response, 2 for invalid args/access denial. Keep stdout limited to status/receipt location; legacy output remains unchanged.
- [ ] Run owning suites GREEN, full new suite, unchanged extraction/typed/bot-crawl tests. Re-run forbidden destination hit-log assertions and legacy byte comparison. Commit explicit paths.

### Task 5: Bounded evaluation and real end-to-end run
**Files:** create bench/jev_eval.py, bench/jev_fixtures.json, tests/test_jev_eval.py; raw outputs outside repo.
**Consumes:** public-page command and engine. No new product interfaces.
**Produces:** reproducible offline/small live evaluation reports, not generalized accuracy claims.

- [ ] Write failing evaluation tests for explicit synthetic label authorship, fixed case IDs, denominator/error/abstention counts, max_attempts enforced across variants, option-order comparison by label not position and no fabricated human ground truth.
- [ ] Implement a stdlib evaluator with at least five synthetic cases: clearly relevant SDK docs, unrelated page, missing evidence, contradictory content and injected instructions. Label source `agent_authored_synthetic`; retain unknown/abstain expectations. Live mode explicit only; five total attempts shared across cases/order variants, never five per case. Save every real receipt and report omissions/unexecuted variants honestly.
- [ ] Run offline tests GREEN. Verify no corpus contains actual credentials or private content.
- [ ] Broker credential ephemerally into task interpreter TYPESAFE_API_KEY (vault service typesafe, allowed get_env, max TTL900); never print broker stdout. Run one real judge-page on an authorized public page after robots/content-signal eligibility. Honor explicit operator public-input attestation without overriding deny. If target denies, choose another permitted public target; never bypass policy. Save command/stdout/receipt paths and measured usage/latency outside repo. This run is not inferred from earlier synthetic access probes.
- [ ] Run capped real fixture evaluation with both pinned model versions only if combined run limits remain satisfied; otherwise execute one version and mark comparison unexecuted. No recurring runs. Preserve provider failures, not synthetic replacements.
- [ ] Inspect every real receipt with runtime validator, verify source hashes and literal locations, compute cost only from reported usage. Do not claim scientific evaluation from this small synthetic set. Commit evaluator/tests/corpus and a sanitized results summary, not raw secrets or runtime cache.

### Task 6: Full regression, package proof, independent review and handoff
**Files:** docs/JEV.md, README short command pointer, final sanitized evidence report; corrections to preceding files only for verified failures.
**Consumes:** Tasks 1–5 complete.
**Produces:** working local artifact and independently reviewed checkpoint; no remote deployment.

- [ ] Run `.venv/bin/python -m unittest discover -s tests -p 'test_*.py' -v` using task env as required, preserving real test count/failures. Run custom harnesses discovered in Task 1 explicitly (including test_v03.py) and assert no failure-count lines/nonzero exit; unittest zero-test import is not coverage. Separate pre-existing environment failures from regressions and resolve blockers before claiming release acceptance.
- [ ] Compare pre/post deterministic fixture bytes and typed.py digest; inspect git diff for unintended legacy changes. Existing commands must not load SDK/read its env/make inference calls.
- [ ] Build wheel/sdist in task env, install wheel into fresh environment outside source. From outside repo execute installed `architect --help`, offline judge-page with controlled test transport/harness, and missing-extra path. Verify optional install separately with mocked transport and no secrets. Do not mistake PYTHONPATH imports for wheel proof.
- [ ] Write docs covering vault-env mapping without values, public-input consent flag, explicit deny precedence, model/version/limits, estimates vs hard ceilings, cache integrity limitations, error codes, receipts and no recurring inference. Include real execution artifact references and test count limits.
- [ ] Run independent whole-branch review with source/spec/plan/test evidence; reviewer must flag validation gaps, cache trust, deadline leaks, redirect/egress, logging and privacy. Fix issues through new RED/GREEN tests before accepting.
- [ ] Scan staged diff for actual credential bytes in memory and secret patterns, run git diff --check, inspect effective identity, commit explicit verified changes and read back SHA/file set/status. Do not push, merge main, publish packages or restart services as part of this task.
- [ ] Final report lists changed artifact, exact tests/live command results, request/cost evidence, reviewer findings resolved, local commit and all remaining unexecuted gates. 'Implemented' requires owning CLI exercised, not only provider probes.

## Plan self-review
All spec sections map to tasks: pure contracts/validation T1, provider/security/optional dependencies T2, budgets/cache/receipts T3, acquisition/privacy/CLI/legacy T4, live evidence/labels T5, full regression/packaging/review T6. Follow-on project integrations remain separate specs as approved. Public network and SDK installation remain fallible; record blockers honestly. Review Focus cases are assigned to T2/T3/T4 tests.

## Execution handoff
Recommendation: subagent-driven, sequential tasks with fresh per-task reviewers and a final whole-branch review. Shared validation/provider/engine contracts have meaningful security consequences; preserve one orchestrator/plan owner. Implementation begins after operator reviews this plan and selects execution method. The operator's prior full-green-light statement approves the written spec and direction; this handoff presents the now-concrete plan for its required review.
