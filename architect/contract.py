"""Solidity / EVM contract lane — the v0.3 node.

Every rule here encodes a real failure mode that has lost real money on
Base and Ethereum. Rules are deliberately conservative: each one emits an
Evidence receipt with the exact line, so a human can judge it in one glance
rather than trusting a score.

What this node is NOT: a formal verifier, a symbolic executor, or a substitute
for a professional audit. It is a fast, honest first pass that points at the
lines worth reading. Reports say so out loud.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass

from . import evidence as _ev

# ── rule table ─────────────────────────────────────────────────────────────
# (rule, severity, regex, detail)

RULES: list[tuple[str, str, str, str]] = [
    # --- access control
    ("tx_origin_auth", "critical",
     r"require\s*\(\s*tx\.origin\s*==",
     "tx.origin for authorization — phishable by any contract the owner calls"),
    ("tx_origin_auth", "critical",
     r"(if|require)\s*\([^)]*\btx\.origin\b",
     "tx.origin in a condition — use msg.sender"),

    # --- external calls / reentrancy
    ("delegatecall", "critical",
     r"\.delegatecall\s*\(",
     "delegatecall executes untrusted code in this contract's storage context"),
    ("selfdestruct", "high",
     r"\bselfdestruct\s*\(|\bsuicide\s*\(",
     "selfdestruct — destroys the contract and force-sends its balance"),
    ("assembly_block", "medium",
     r"\bassembly\s*\{",
     "inline assembly — bypasses Solidity's safety checks; needs line-by-line review"),

    # --- arithmetic / overflow era
    ("unchecked_block", "medium",
     r"\bunchecked\s*\{",
     "unchecked block — arithmetic cannot revert on overflow"),

    # --- randomness
    ("weak_randomness", "high",
     r"keccak256\s*\(\s*abi\.encodePacked\s*\([^)]*(block\.(timestamp|number|difficulty|prevrandao)|blockhash)",
     "randomness derived from block variables — miner/validator influenced"),
    ("weak_randomness", "medium",
     r"\bblock\.(difficulty|prevrandao)\b",
     "block.difficulty/prevrandao is not a safe entropy source"),

    # --- value handling
    ("arbitrary_send", "high",
     r"\.transfer\s*\(\s*(address\s*\(\s*this\s*\))?\.balance\s*\)|\.transfer\s*\(\s*address\s*\(\s*this\s*\)\.balance",
     "sends the entire contract balance — check the recipient and the amount"),
    ("transfer_in_loop", "high",
     r"for\s*\([^)]*\)[^{]*\{[^}]*\.transfer\s*\(",
     "transfer inside a loop — one reverting recipient blocks the whole batch"),
    ("send_ignored", "medium",
     r"\.send\s*\([^)]*\)\s*;",
     ".send returns a bool and reverts nothing — an unchecked false is a silent loss"),

    # --- pragma / compiler
    ("floating_pragma", "medium",
     r"pragma\s+solidity\s+[\^>]",
     "floating pragma — the deployed bytecode depends on a compiler you did not pin"),

    # --- upgradeability
    ("unprotected_initialize", "critical",
     r"function\s+initialize\s*\(",
     "initializer present — must be guarded with initializer/reinitializer or anyone can take ownership"),
    ("public_initializer", "critical",
     r"function\s+initialize\s*\([^)]*\)\s*public\b",
     "public initializer with no modifier — front-runnable to seize the proxy"),

    # --- D0xed / Base specific
    ("b20_issuer_control", "high",
     r"\b(seize|setPause|pause\s*\(|unpause\s*\(|freeze|blacklist|blocklist)\b",
     "issuer-level seize/pause/freeze surface — holders cannot opt out; treat as centralised control"),
    ("b20_precompile", "high",
     r"0x[bB]20[0-9a-fA-F]{2,}",
     "B20 precompile token standard — issuer seize/pause powers are enforced by the chain, not the contract"),

    # --- common footguns
    ("timestamp_dependence", "low",
     r"\bblock\.timestamp\b",
     "block.timestamp is validator-manipulable within a small window"),
    ("approve_race", "low",
     r"function\s+approve\s*\(",
     "ERC-20 approve race — prefer increaseAllowance or set-to-zero-then-set"),
    ("unbounded_loop", "medium",
     r"for\s*\([^;]*;\s*[^;]*\.length\s*;",
     "loop bound by an unbounded array — gas griefing / out-of-gas DoS"),
    ("hardcoded_address", "info",
     r"address\s*\(\s*0x[0-9a-fA-F]{40}\s*\)\s*;",
     "hardcoded address — confirm it is intentional and correct for every chain"),
]

# Reentrancy needs ordering, not a single line: an external call followed by a
# state write in the same function body is the classic pattern.
_CALL = re.compile(
    r"\.call\s*\{|\.transfer\s*\(|\.send\s*\(|\.call\s*\(|"
    r"\bIERC20\w*\([^)]*\)\.(transfer|transferFrom|safeTransfer)\w*\s*\(")
_STATE_WRITE = re.compile(
    r"^\s*(?:\w+(?:\[\S*\])?(?:\.\w+)?)\s*(?:[-+*/]?=|\+\+|--)\s*[^=]")
_WINDOW = 12

# Some patterns only exist ACROSS lines. A `keccak256(abi.encodePacked(` whose
# arguments sit on the following line evades every per-line rule — and a missed
# finding is worse than a false one, because the report is wrong in the
# direction people trust. This pass scans the whole source with DOTALL.
_MULTILINE_RULES: list[tuple[str, str, str, str]] = [
    ("weak_randomness", "high",
     r"keccak256\s*\(\s*abi\.encodePacked\s*\([^;]{0,200}?"
     r"(?:block\.(?:prevrandao|difficulty|number|timestamp)\b|blockhash\s*\()",
     "seed derived from a block variable across lines — influenceable by the "
     "block producer and by simulating against a known block"),
]

# Test-only code is still code, but a reentrancy in a mock router is not a
# production risk. Findings here are kept and annotated, never dropped —
# silently hiding them would be the same dishonesty as inflating them.
_TEST_PATH = re.compile(
    r"(^|/)(tests?|mocks?|fixtures?|examples?)(/|$)"
    r"|Mock[A-Z]|\.t\.sol$|\.test\.|\.spec\.", re.I)
_DOWNGRADE = {"critical": "high", "high": "medium", "medium": "low",
              "low": "info", "info": "info"}


def is_test_path(rel: str) -> bool:
    """True when the path is obviously test/mock/fixture code."""
    return bool(_TEST_PATH.search(rel.replace(os.sep, "/")))


def _solidity_files(root: str) -> list[str]:
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames
                       if d not in {"node_modules", ".next", "lib", "vendor",
                                    "out", "cache", "artifacts", ".git"}]
        for fn in filenames:
            if fn.endswith(".sol"):
                out.append(os.path.join(dirpath, fn))
    return out


def scan_source(source: str) -> list[tuple[str, str, int, str]]:
    """Rule-based pass. Returns (rule, severity, line, detail)."""
    hits: list[tuple[str, str, int, str]] = []
    lines = source.splitlines()

    # Multi-line pass runs FIRST so the single-line rules can be told which
    # lines a more specific match already covers.
    ml_spans: list[tuple[int, int]] = []
    for rule, severity, pattern, detail in _MULTILINE_RULES:
        for m in re.finditer(pattern, source, re.S):
            start = source.count("\n", 0, m.start()) + 1
            end = source.count("\n", 0, m.end()) + 1
            ml_spans.append((start, end))
            hits.append((rule, severity, start, detail))

    def _covered(line: int) -> bool:
        return any(a <= line <= b for a, b in ml_spans)

    for rule, severity, pattern, detail in RULES:
        rx = re.compile(pattern)
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("//") or stripped.startswith("*"):
                continue
            if not rx.search(line):
                continue
            # The generic block-variable rule must not re-report a line that a
            # specific seed-derivation match already covers: one issue, one
            # finding. Two findings for one problem is how a report loses trust.
            if rule == "weak_randomness" and detail.startswith("block.") and _covered(i):
                continue
            hits.append((rule, severity, i, detail))

    # Low-level calls: a finding only when the success flag goes unchecked.
    # Flagging every `.call` would fire on correct checks-effects-interactions
    # code, and a rule that cries wolf on safe code teaches people to ignore it.
    for i, line in enumerate(lines):
        if ".call" not in line or line.strip().startswith("//"):
            continue
        vm = re.search(r"\(\s*bool\s+(\w+)\s*,", line)
        if vm:
            var = vm.group(1)
            window = "\n".join(lines[i + 1:i + 4])
            if re.search(rf"require\s*\(\s*{var}\b", window) or \
               re.search(rf"if\s*\(\s*!?\s*{var}\b", window):
                continue
            hits.append(("unchecked_call", "high", i + 1,
                         f"low-level call result '{var}' is captured but never checked"))
        elif re.search(r"^\s*[^=;]+\.call\s*[({]", line):
            hits.append(("unchecked_call", "high", i + 1,
                         "low-level call whose success flag is discarded entirely"))

    # Reentrancy: external call then state write within a short window.
    for i, line in enumerate(lines):
        if not _CALL.search(line):
            continue
        for j in range(i + 1, min(i + 1 + _WINDOW, len(lines))):
            nxt = lines[j]
            if "}" in nxt and "{" not in nxt:
                break
            stripped = nxt.strip()
            if not stripped or stripped.startswith("//"):
                continue
            if _STATE_WRITE.match(nxt) and "==" not in nxt:
                # A write that lives inside an `if (!ok) { ... }` branch is
                # reached ONLY when the call failed — and a failed call
                # reverts, so nothing the callee did survived. Flagging it is
                # a false positive, and false CRITICALS are how a scanner
                # trains its reader to ignore it.
                guard = "\n".join(lines[i:j])
                if re.search(r"if\s*\(\s*!\s*\w+\s*\)\s*\{", guard):
                    continue
                hits.append((
                    "reentrancy_state_after_call", "critical", j + 1,
                    f"state written after an external call at line {i + 1} — "
                    "an attacker can re-enter before the write lands"))
                break
    return hits


def audit_contracts(root: str, node: str = "contract") -> list[_ev.Evidence]:
    """Scan every .sol file under root and return Evidence receipts."""
    findings: list[_ev.Evidence] = []
    for abspath in _solidity_files(root):
        rel = os.path.relpath(abspath, root)
        try:
            with open(abspath, "r", encoding="utf-8", errors="replace") as fh:
                source = fh.read()
        except OSError:
            continue
        lines = source.splitlines()
        try:
            file_hash = _ev.sha256_file(abspath)
        except OSError:
            continue

        seen: set[tuple[str, int]] = set()
        in_test = is_test_path(rel)
        for rule, severity, line, detail in scan_source(source):
            if (rule, line) in seen:
                continue
            seen.add((rule, line))
            if in_test:
                severity = _DOWNGRADE[severity]
                detail += " [test/mock path — not deployed; severity stepped down]"
            ev = _ev.capture(root, rel, line, rule, severity, detail, node=node,
                             lines=lines, file_hash=file_hash)
            if ev:
                findings.append(ev)
    return findings