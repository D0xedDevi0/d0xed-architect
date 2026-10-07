"""Swarm nodes — small, single-purpose, independently readable.

The argument for small nodes is not elegance, it is auditability: you can read
`secrets` in five minutes and know exactly what it does. A 40,000-line security
platform you cannot, so you end up trusting it instead of checking it.

Every node returns Evidence receipts. Nodes that can only produce facts without
a line number put those in `stats`, never in findings — "no finding without
evidence" applies to the tool itself.
"""

from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass, field

from . import audit as _audit
from . import contract as _contract
from . import events as _events
from . import evidence as _ev

SOURCE_EXT = {
    ".py", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".go", ".rs",
    ".sol", ".java", ".rb", ".php", ".sh", ".bash", ".yml", ".yaml",
    ".json", ".toml", ".env", ".cfg", ".ini",
}
SKIP_DIRS = {"node_modules", ".next", ".git", "dist", "build", "out", "cache",
             "artifacts", "vendor", "lib", "__pycache__", ".venv", "venv",
             ".turbo", "coverage", ".openclaw"}


@dataclass
class NodeResult:
    name: str
    findings: list = field(default_factory=list)
    stats: dict = field(default_factory=dict)
    duration: float = 0.0
    error: str = ""


def _eligible_files(root: str) -> list[str]:
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            ext = os.path.splitext(fn)[1].lower()
            if ext in SOURCE_EXT or fn in {"Dockerfile", "Makefile"}:
                out.append(os.path.join(dirpath, fn))
    return out


def _read(abspath: str) -> str:
    with open(abspath, "r", encoding="utf-8", errors="replace") as fh:
        return fh.read()


# ── node: secrets ──────────────────────────────────────────────────────────

def node_secrets(root: str) -> NodeResult:
    """Credential-shaped strings, with the documented-example allowlist applied."""
    res = NodeResult("secrets")
    files = _eligible_files(root)
    res.stats["files"] = len(files)
    for abspath in files:
        rel = os.path.relpath(abspath, root)
        try:
            source = _read(abspath)
            file_hash = _ev.sha256_file(abspath)
        except OSError:
            continue
        lines = source.splitlines()
        seen: set = set()
        for rule, pattern, score in _audit.SECRET_RULES:
            for m in _audit._range(source, pattern):
                line = source.count("\n", 0, m.start()) + 1
                # One line can match a rule twice (e.g. an EC *and* a PKCS8
                # header on the same line); identical snippet means one finding.
                if (rel, line, rule) in seen:
                    continue
                ev = _ev.capture(
                    root, rel, line, f"secret:{rule}", _sev(score),
                    _audit._mask(m.group(0)), node="secrets",
                    lines=lines, file_hash=file_hash)
                if ev:
                    seen.add((rel, line, rule))
                    res.findings.append(ev)
    return res


def _sev(score: int) -> str:
    return ("critical" if score >= 9 else "high" if score >= 7
            else "medium" if score >= 5 else "low")


# ── node: contract ─────────────────────────────────────────────────────────

def node_contract(root: str) -> NodeResult:
    """Solidity / EVM lane — see contract.py for the rule rationale."""
    res = NodeResult("contract")
    files = _contract._solidity_files(root)
    res.stats["files"] = len(files)
    res.findings = _contract.audit_contracts(root)
    return res


# ── node: repo ─────────────────────────────────────────────────────────────

def node_repo(root: str) -> NodeResult:
    """Structure only: language mix, oversized files, entrypoints.

    This node produces facts, not findings. Flagging a 900-line file as a
    'problem' would be an opinion dressed as evidence.
    """
    res = NodeResult("repo")
    langs: dict = {}
    big: list = []
    total_bytes = 0
    files = _eligible_files(root)
    for abspath in files:
        ext = os.path.splitext(abspath)[1].lower() or "(none)"
        try:
            size = os.path.getsize(abspath)
        except OSError:
            continue
        total_bytes += size
        langs[ext] = langs.get(ext, 0) + 1
        if size > 200_000:
            big.append((os.path.relpath(abspath, root), size))

    res.stats.update({
        "files": len(files),
        "bytes": total_bytes,
        "languages": dict(sorted(langs.items(), key=lambda x: -x[1])[:12]),
        "oversized": big[:8],
    })
    return res


# ── node: deps ─────────────────────────────────────────────────────────────

_UNPINNED = re.compile(r'"[^"]+"\s*:\s*"(\*|latest|)"')


def node_deps(root: str) -> NodeResult:
    """Dependency inventory + unpinned specifiers.

    Honest scope: this does NOT consult a CVE database. It reports what is
    declared and what is unpinned, anchored to the line it read it from.
    Claiming vulnerability coverage without a feed would be exactly the
    greenwash this project exists to avoid.
    """
    res = NodeResult("deps")
    manifests = {"package.json", "requirements.txt", "pyproject.toml",
                 "Cargo.toml", "go.mod"}
    found = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            if fn not in manifests:
                continue
            found += 1
            abspath = os.path.join(dirpath, fn)
            rel = os.path.relpath(abspath, root)
            try:
                source = _read(abspath)
                file_hash = _ev.sha256_file(abspath)
            except OSError:
                continue
            lines = source.splitlines()
            if fn == "package.json":
                for i, line in enumerate(lines, 1):
                    m = _UNPINNED.search(line)
                    if m:
                        ev = _ev.capture(
                            root, rel, i, "dep:unpinned", "medium",
                            f"dependency range '{m.group(1) or '(empty)'}' "
                            "resolves to whatever is newest at install time",
                            node="deps", lines=lines, file_hash=file_hash)
                        if ev:
                            res.findings.append(ev)
            elif fn == "requirements.txt":
                for i, line in enumerate(lines, 1):
                    s = line.strip()
                    if s and not s.startswith("#") and "==" not in s:
                        ev = _ev.capture(
                            root, rel, i, "dep:unpinned", "medium",
                            "requirement without a pinned == version",
                            node="deps", lines=lines, file_hash=file_hash)
                        if ev:
                            res.findings.append(ev)

    res.stats["manifests"] = found
    res.stats["files"] = found
    lockfiles = [f for f in ("package-lock.json", "yarn.lock", "pnpm-lock.yaml",
                             "uv.lock", "poetry.lock", "Cargo.lock")
                 if os.path.exists(os.path.join(root, f))]
    res.stats["lockfiles"] = lockfiles
    if found and not lockfiles:
        res.stats["note"] = "manifests present with no lockfile — builds are not reproducible"
    return res


# ── registry + runner ──────────────────────────────────────────────────────

NODES = {
    "repo": node_repo,
    "secrets": node_secrets,
    "contract": node_contract,
    "deps": node_deps,
}

DEFAULT_NODES = ("repo", "secrets", "deps")


def run_node(name: str, root: str, bus: _events.EventBus) -> NodeResult:
    bus.emit(_events.NODE_START, node=name)
    t0 = time.time()
    try:
        res = NODES[name](root)
        res.duration = time.time() - t0
    except Exception as exc:  # noqa: BLE001 - one bad node must not kill the swarm
        res = NodeResult(name, duration=time.time() - t0,
                         error=f"{type(exc).__name__}: {exc}")
        bus.emit(_events.NODE_ERROR, node=name, error=res.error)
        return res

    for f in sorted(res.findings, key=lambda x: x.severity):
        bus.emit(_events.FINDING, node=name, severity=f.severity, rule=f.rule,
                 where=f"{f.path}:{f.line}", receipt=f.receipt)
    bus.emit(_events.NODE_DONE, node=name, findings=len(res.findings),
             files=res.stats.get("files", 0), duration=res.duration)
    return res


def run_swarm(root: str, node_names, bus: _events.EventBus,
              max_workers: int = 4) -> dict:
    """Place the chosen nodes and collect their evidence.

    Nodes run concurrently but report through one bus, so the view reflects the
    real order things happened in, not a scripted animation.
    """
    import concurrent.futures as cf

    names = [n for n in node_names if n in NODES]
    unknown = [n for n in node_names if n not in NODES]
    if unknown:
        bus.emit(_events.NOTE, msg=f"ignoring unknown node(s): {', '.join(unknown)}")

    t0 = time.time()
    bus.emit(_events.SWARM_START, nodes=names)

    results: dict[str, NodeResult] = {}
    with cf.ThreadPoolExecutor(max_workers=max_workers) as ex:
        futs = {ex.submit(run_node, n, root, bus): n for n in names}
        for fut in cf.as_completed(futs):
            n = futs[fut]
            results[n] = fut.result()

    findings = [f for r in results.values() for f in r.findings]
    duration = time.time() - t0
    bus.emit(_events.SWARM_DONE, findings=len(findings), duration=duration,
             manifest_root=_ev.manifest_root(findings))
    return {
        "results": results,
        "findings": findings,
        "duration": duration,
        "nodes": {n: {"findings": len(r.findings), "duration": round(r.duration, 3),
                      "error": r.error, **{k: v for k, v in r.stats.items()
                                           if k != "languages"}}
                  for n, r in results.items()},
    }