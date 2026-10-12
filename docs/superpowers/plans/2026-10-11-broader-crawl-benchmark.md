# Broader Crawl Benchmark Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce reproducible, clearly qualified static and JS-dependent crawl observations for Architect and Crawl4AI without overwriting archived results or conflating extraction quality with crawl throughput.

**Architecture:** Extend the existing subprocess benchmark driver to run a named target/mode matrix and write an immutable, per-run JSON artifact. Keep tool runners process-isolated and record both successful metrics and explicit failures; evaluate reached pages and content presence, not just elapsed time. The existing one-target `compare.py` interface and `bench-results.json` remain compatible.

**Tech Stack:** Python 3.11+, stdlib subprocess/JSON/unittest, current `.venv` and `bench/.venv`, Playwright/Crawl4AI as already installed.

**Spec:** `docs/superpowers/specs/2026-10-10-typed-extraction-and-devin-roadmap-design.md` §Scope sequencing (item 2), §Tests and measurements; `bench/README.md` fairness limitations.

## Global Constraints

- A bounded observation is not a general performance claim; no overall speed winner from a small sample.
- Respect target robots/access policy. Never pay x402 or bypass a denied URL for the sake of a score.
- Each tool gets its own process; preserve actual exit code and stderr on failures, and do not publish fabricated metrics.
- Record target, run timestamp, exact commit, page cap/depth, tool mode, pages reached, wall time, RSS, output size, robots posture, and browser/cache posture.
- Separate static/JS-dependent targets and crawl-speed figures from typed-extraction accuracy fixtures; label differences in the tools' robots defaults and Crawl4AI's sequential `arun` loop.
- Keep `bench/compare.py URL [max_pages] [depth]` behavior and existing archived JSON stable; no new mandatory dependency.

## Review Focus

- A tool exits nonzero but prints `BENCH_JSON`: mark it as failed, not success (Task 1 test).
- A target yields one page because redirect/robots blocked the frontier: report that fact, not a speed victory (Task 2 test).
- An SPA shell has no useful post-JS content: count usable content separately from page success (Task 2 test).
- A timeout or absent browser/runtime: record unavailable, do not substitute the other tool's output (Task 1 test).
- Per-process RSS and wall time must describe the same subprocess; distinguish runner-internal timing from driver elapsed timing (Task 1 test).

---

## File Map

- Modify `bench/compare.py`: accept a safe optional output path/mode while keeping positional interface; validate exit status, expose subprocess driver wall time and failure reason.
- Create `bench/benchmark_matrix.py`: named targets/modes, bounded orchestrator, separate JSON artifact, summary of actual reached pages and observed content.
- Modify `bench/tool_architect.py`, `bench/tool_crawl4ai.py` only where the tests show a metric gap (e.g. resolved final URL, content marker); avoid altering policy behavior.
- Create `tests/test_benchmark_matrix.py`: subprocess/fixture tests for aggregation, failure handling, and output format.
- Modify `bench/README.md`: exact invocation, raw artifact path, environment, methodology, policy caveats, and limits; retain historical results unchanged.

### Task 1: Correct Subprocess Result Semantics

**Files:** Modify `bench/compare.py`; create `tests/test_benchmark_matrix.py`.

**Interfaces:** `run_one(name, python, script, url, max_pages, depth, timeout=900, *, env_overrides=None) -> dict`; returned result includes `process_exit_code`, `driver_wall_s`, and error on nonzero exit or timeout. Existing positional call continues to work.

- [ ] **Step 1:** Write tests: fake subprocess output with `BENCH_JSON` and nonzero exit must be an error; timeout must preserve its duration; a successful result preserves runner metrics and attaches process/driver fields. Mock only the subprocess boundary.
- [ ] **Step 2:** Run `.venv/bin/python -m unittest discover -s tests -p test_benchmark_matrix.py -v`; confirm the expected failures.
- [ ] **Step 3:** Implement the minimal `run_one` changes; bound/sanitize failure detail and keep the original `main()` positional behavior.
- [ ] **Step 4:** Rerun the targeted tests and `git diff --check`; confirm pass.
- [ ] **Step 5:** Commit this tested change separately.

### Task 2: Named Matrix and Content-Presence Receipts

**Files:** Create `bench/benchmark_matrix.py`; add tests to `tests/test_benchmark_matrix.py`; modify runners only if necessary.

**Interfaces:** `run_matrix(targets: list[dict], *, max_pages: int, depth: int, repetitions: int, output: str) -> dict`. Targets explicitly identify `name`, `url`, `kind` (`static`/`js`), and optional literal `content_marker`; modes are Architect HTTP, Architect ladder, and Crawl4AI browser. Return individual runs and summaries, not a single winning score.

- [ ] **Step 1:** Write a local HTTP fixture with a static page, a JS shell whose marker appears only after script execution, robots allow/deny, and an intentional redirect. Tests assert exact run count, zero forbidden hits in Architect's guarded HTTP/ladder modes, stable target/mode labels, separate success/content flags, one-page warning, and no metrics invented for failed runs. Crawl4AI's independent default robots posture is measured separately, not asserted as equivalent.
- [ ] **Step 2:** Run the targeted test; confirm failure for missing orchestrator/metrics.
- [ ] **Step 3:** Implement the smallest matrix CLI/orchestrator and content marker reporting needed to pass. Require positive bounded caps/repetitions, explicit destinations, per-run cold process, and unique output path; do not overwrite archived results. Use policy-aware Architect modes as shipped and disclose Crawl4AI's independent default robots behavior.
- [ ] **Step 4:** Rerun targeted tests; confirm the local browser actually executes the JS content on the configured Playwright path and Architect's guarded modes leave the denied hit log empty.
- [ ] **Step 5:** Commit the tested matrix separately.

### Task 3: Real Bounded Observations and Documentation

**Files:** Add `bench/results/<dated>-multi-target.json` from real execution; modify `bench/README.md`.

**Interfaces:** Matrix CLI with 2–3 robots-allowed real targets covering at least one mostly static and one JS-dependent site. If a live target is denied, unreachable, or ambiguous, record it as such; do not quietly replace it with a cherry-picked success. One local fixture run remains a deterministic functional check, not a live speed datapoint.

- [ ] **Step 1:** Check target robots and render/browser prerequisites, then run the matrix with small explicit caps and repetitions; print the artifact path. Do not launch paid model calls or x402 settlement.
- [ ] **Step 2:** Independently parse the artifact and verify enumerated run count, per-tool exit codes, pages reached, content markers, commit hash, timestamps, and absence of secrets. Read actual output, not just the orchestrator success line.
- [ ] **Step 3:** Update README with exact targets/config/results, limitations (small sample, sequential Crawl4AI `arun`, different robots posture, cold browser startup), and separate typed-quality pointer. No universal speed or accuracy claim.
- [ ] **Step 4:** Run all discovered tests plus legacy standalone scripts, compileall, `git diff --check`, and staged secret scan; resolve any reviewer findings before publishing.
- [ ] **Step 5:** Commit/push the observed artifact, docs and tests only after verification; read back remote SHA and artifact path. Do not merge/deploy or claim DEVin activation.

## Execution and handoff

This plan covers the benchmark increment only. Packaging and DEVin are separate subsystems requiring their own release/authorization design gates. A read-only Base RPC query during planning reported `ownerOf(706) = 0x23129c0472172D75bEd1e6dd061301796760Ecd9` and `erc8004AgentIdByLooper(706) = 87226`; this verifies only current on-chain mapping at query time, not wallet control, bot authorization, registry metadata, or activation. Before DEVin actions, re-query and verify all of those independently.
