"""Deep STATIC architecture/debug report for a GitHub repository.

Builds on `github_audit` (same URL parsing, same SSRF-pinned fetch, same
host-gated token handling) but goes further: it extracts the tarball to an
isolated temp tree and reuses `architect.audit.audit_repo` + `architect.graph`
to produce, in addition to the secret/risk findings:

  * language breakdown, module count, entrypoints
  * top-imported modules and any import CYCLES
  * dependency manifests present (with a bounded sample of their deps)
  * CI workflow files present (.github/workflows)
  * test files found
  * TODO / FIXME counts

Nothing is ever executed: the tree is only ever read as text by `audit_repo`
and this module's own bounded scans. Every finding is labelled STATIC-ONLY and
carries `path:line` plus sha256 receipts; a supplied token never appears in any
finding, report, or error string.
"""
from __future__ import annotations

import io
import json
import os
import re
import shutil
import tarfile
import tempfile
import urllib.parse
from dataclasses import dataclass, field

from architect import safe_fetch
from architect.audit import CODE_EXT, IMPORT_JS, IMPORT_PY, Finding, audit_repo
from architect.evidence import (Evidence, manifest_root, severity_counts,
                                sha256_bytes)
from architect.graph import Graph

from .github_audit import (AuditDenied, AuditLimits, _BRANCH_RE, _auth_headers,
                           _masked_snippet, _rel_path, _skip_path,
                           parse_repo_url)

# Secondary bounded-output caps (safety limits, not preferences).
_MAX_TOP_IMPORTS = 10
_MAX_CYCLES = 5
_MAX_CYCLE_NODES = 12
_MAX_DEPS = 12
_MAX_MANIFEST_BYTES = 50_000
_MAX_CODE_BYTES = 200_000
_MAX_TESTS = 25
_MAX_WORKFLOWS = 25

MANIFEST_NAMES = ("requirements.txt", "pyproject.toml", "package.json",
                  "go.mod", "Cargo.toml")
_TEST_BASENAME = re.compile(
    r"(^test_|_test\.|\.test\.|\.spec\.|^test\.|Test\.(java|kt|cs)$)", re.I)
_TEST_DIR = re.compile(r"(^|/)(tests?|__tests__|spec)/")


@dataclass
class DeepReport:
    owner: str
    repo: str
    ref: str
    mode: str = "static-only"
    files_scanned: int = 0
    bytes_scanned: int = 0
    languages: dict = field(default_factory=dict)
    modules: int = 0
    entrypoints: list = field(default_factory=list)
    top_imports: list = field(default_factory=list)   # [(module, count)]
    cycles: list = field(default_factory=list)        # [[file, ...], ...]
    manifests: dict = field(default_factory=dict)     # name -> [dep sample, ...]
    workflows: list = field(default_factory=list)
    tests: list = field(default_factory=list)
    todo_count: int = 0
    fixme_count: int = 0
    findings: list = field(default_factory=list)      # Evidence
    truncated: bool = False
    manifest_root: str = ""

    def severity_counts(self) -> dict:
        return severity_counts(self.findings)


# ── safe extraction ────────────────────────────────────────────────────────

def _safe_rel(member_name: str) -> str | None:
    rel = _rel_path(member_name)
    if not rel or rel.startswith("/") or "\\" in rel:
        return None
    parts = rel.split("/")
    if any(seg in ("", ".", "..") for seg in parts):
        return None
    return rel


def _extract_tarball(data: bytes, limits: AuditLimits) -> tuple[str, bool]:
    """Extract a gzipped tarball into a fresh temp dir, traversal-safe.

    Returns (root_dir, truncated). Skips symlinks/hardlinks and skip-dirs, and
    enforces the file/byte caps so a hostile archive can't fill the disk.
    """
    root = tempfile.mkdtemp(prefix="devin-deep-")
    truncated = False
    total = 0
    files = 0
    try:
        tf = tarfile.open(fileobj=io.BytesIO(data), mode="r:gz")
    except Exception as e:
        raise AuditDenied("not a readable archive") from e
    try:
        for member in tf:
            if files >= limits.max_files or total >= limits.max_total_bytes:
                truncated = True
                break
            if not member.isfile() or member.issym() or member.islnk():
                continue
            rel = _safe_rel(member.name)
            if rel is None or _skip_path(rel):
                continue
            if member.size > limits.max_file_bytes:
                truncated = True
                continue
            f = tf.extractfile(member)
            if f is None:
                continue
            raw = f.read(limits.max_file_bytes + 1)
            if len(raw) > limits.max_file_bytes:
                truncated = True
                continue
            if total + len(raw) > limits.max_total_bytes:
                truncated = True
                break
            dest = os.path.join(root, *rel.split("/"))
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            with open(dest, "wb") as out:
                out.write(raw)
            files += 1
            total += len(raw)
    finally:
        tf.close()
    return root, truncated


# ── metadata scan (manifests, workflows, tests, TODO/FIXME) ────────────────

def _deps_requirements(text: str) -> list[str]:
    out = []
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#") or s.startswith("-") or s.startswith("--"):
            continue
        out.append(s[:_MAX_DEPS * 4])
        if len(out) >= _MAX_DEPS:
            break
    return out


def _deps_pyproject(text: str) -> list[str]:
    out = []
    idx = text.lower().find("dependencies")
    if idx < 0:
        return out
    for line in text[idx:].splitlines()[1:]:
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        m = re.search(r"[\"']([^\"']+)[\"']", s)
        if m:
            out.append(m.group(1)[:_MAX_DEPS * 4])
        if len(out) >= _MAX_DEPS:
            break
    return out


def _deps_package_json(text: str) -> list[str]:
    try:
        j = json.loads(text)
    except Exception:
        return []
    out = []
    for section in ("dependencies", "devDependencies"):
        for name in (j.get(section) or {}):
            out.append(str(name)[:_MAX_DEPS * 4])
            if len(out) >= _MAX_DEPS:
                return out
    return out


def _deps_go_mod(text: str) -> list[str]:
    out = []
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("//"):
            continue
        if s.startswith("module ") or s.startswith("require ") or s.startswith("\t"):
            out.append(s[:_MAX_DEPS * 4])
            if len(out) >= _MAX_DEPS:
                break
    return out


def _deps_cargo(text: str) -> list[str]:
    out = []
    lines = text.splitlines()
    in_deps = False
    for line in lines:
        s = line.strip()
        if s.startswith("[") and s.endswith("]"):
            in_deps = s.strip("[]").strip().lower() in ("dependencies", "dev-dependencies", "build-dependencies")
            continue
        if in_deps and s and not s.startswith("#"):
            key = s.split("=", 1)[0].strip().strip("\"'")
            out.append(key[:_MAX_DEPS * 4])
            if len(out) >= _MAX_DEPS:
                break
    return out


_MANIFEST_PARSERS = {
    "requirements.txt": _deps_requirements,
    "pyproject.toml": _deps_pyproject,
    "package.json": _deps_package_json,
    "go.mod": _deps_go_mod,
    "Cargo.toml": _deps_cargo,
}


def _read_small(path: str, cap: int) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read(cap)
    except OSError:
        return ""


def _metadata_scan(root: str, report: DeepReport) -> None:
    found_manifests: set[str] = set()
    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = os.path.relpath(dirpath, root)
        dirnames[:] = [d for d in dirnames
                       if d not in _SKIP_SET and not d.startswith(".venv")]
        for fn in filenames:
            rel = os.path.relpath(os.path.join(dirpath, fn), root).replace(os.sep, "/")
            if fn in MANIFEST_NAMES and fn not in found_manifests \
                    and len(report.manifests) < len(MANIFEST_NAMES):
                found_manifests.add(fn)
                text = _read_small(os.path.join(dirpath, fn), _MAX_MANIFEST_BYTES)
                sample = _MANIFEST_PARSERS[fn](text)
                report.manifests[fn] = sample
            if ".github/workflows/" in rel and fn.endswith((".yml", ".yaml")) \
                    and len(report.workflows) < _MAX_WORKFLOWS:
                report.workflows.append(rel)
            if (_TEST_BASENAME.search(fn) or _TEST_DIR.search(rel)) \
                    and len(report.tests) < _MAX_TESTS:
                report.tests.append(rel)
            if fn.endswith(CODE_EXT_TUPLE):
                text = _read_small(os.path.join(dirpath, fn), _MAX_CODE_BYTES)
                report.todo_count += len(re.findall(r"\bTODO\b", text))
                report.fixme_count += len(re.findall(r"\bFIXME\b", text))


_SKIP_SET = {".git", "node_modules", ".next", "dist", "build", "__pycache__",
             ".venv", "venv", ".venv-ml", "vendor", "target", ".cache",
             "site-packages"}
CODE_EXT_TUPLE = tuple(CODE_EXT)


# ── import graph + cycles ──────────────────────────────────────────────────

def _module_index(py_files: list[str]) -> dict[str, str]:
    idx: dict[str, str] = {}
    for rel in py_files:
        mod = rel[:-3].replace("/", ".")
        if mod.endswith(".__init__"):
            mod = mod[:-9]
        idx[mod] = rel
    return idx


def _import_edges(root: str, files: list[str]) -> dict[str, set[str]]:
    py_files = [r for r in files if r.endswith(".py")]
    js_files = [r for r in files if r.endswith(
        (".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"))]
    js_set = set(js_files)
    module_idx = _module_index(py_files)
    edges: dict[str, set[str]] = {}
    for rel in py_files:
        src = _read_small(os.path.join(root, rel), _MAX_CODE_BYTES)
        deps: set[str] = set()
        for a, b in IMPORT_PY.findall(src):
            mod = a or b
            if not mod or mod.startswith("_"):
                continue
            target = module_idx.get(mod)
            if target is None:
                target = module_idx.get(mod.split(".")[0])
            if target and target != rel:
                deps.add(target)
        if deps:
            edges[rel] = deps
    for rel in js_files:
        src = _read_small(os.path.join(root, rel), _MAX_CODE_BYTES)
        deps = set()
        for a, b in IMPORT_JS.findall(src):
            mod = a or b
            if not mod or not mod.startswith("."):
                continue
            base = os.path.normpath(os.path.join(os.path.dirname(rel), mod))
            for cand in (base, base + ".js", base + ".ts", base + ".jsx",
                         base + ".tsx", base + "/index.js", base + "/index.ts"):
                if cand in js_set and cand != rel:
                    deps.add(cand)
                    break
        if deps:
            edges[rel] = deps
    return edges


def _find_cycles(adj: dict[str, set[str]]) -> list[list[str]]:
    """Tarjan SCC; a cycle is an SCC with >1 node or a self-loop."""
    index: dict[str, int] = {}
    low: dict[str, int] = {}
    on_stack: set[str] = set()
    stack: list[str] = []
    sccs: list[list[str]] = []
    counter = [0]

    def strongconnect(v: str) -> None:
        index[v] = low[v] = counter[0]
        counter[0] += 1
        stack.append(v)
        on_stack.add(v)
        for w in adj.get(v, ()):
            if w not in index:
                strongconnect(w)
                low[v] = min(low[v], low[w])
            elif w in on_stack:
                low[v] = min(low[v], index[w])
        if low[v] == index[v]:
            comp: list[str] = []
            while True:
                w = stack.pop()
                on_stack.discard(w)
                comp.append(w)
                if w == v:
                    break
            sccs.append(comp)

    for v in adj:
        if v not in index:
            strongconnect(v)

    cycles = []
    for comp in sccs:
        if len(comp) > 1 or (len(comp) == 1 and comp[0] in adj.get(comp[0], ())):
            cycles.append(sorted(comp)[:_MAX_CYCLE_NODES])
    return cycles[:_MAX_CYCLES]


# ── findings → evidence (with receipts, masked) ────────────────────────────

def _to_evidence(root: str, f: Finding, cache: dict) -> Evidence | None:
    rel = f.path.replace(os.sep, "/")
    if rel not in cache:
        try:
            with open(os.path.join(root, rel), "rb") as fh:
                raw = fh.read()
            fhash = sha256_bytes(raw)
            lines = raw.decode("utf-8", "replace").splitlines()
        except OSError:
            cache[rel] = (None, [])
            return None
        cache[rel] = (fhash, lines)
    fhash, lines = cache[rel]
    if not fhash or f.line < 1 or f.line > len(lines):
        return None
    snippet = _masked_snippet(lines[f.line - 1])
    return Evidence(rule=f.kind, severity=f.severity, path=rel, line=f.line,
                    snippet=snippet, file_sha256=fhash,
                    snippet_sha256=sha256_bytes(snippet.encode()),
                    detail=f.detail or "")


# ── orchestration ──────────────────────────────────────────────────────────

def deep_repo_report(url: str, fetch, limits: AuditLimits | None = None,
                     timeout: float = 60.0, token: str | None = None) -> DeepReport:
    """Fetch and deeply inspect a repo. Same refusals as `audit_public_repo`;
    with a `token` private repos are auditable (token never leaks).
    """
    limits = limits or AuditLimits()
    root = None
    try:
        ref = parse_repo_url(url)
        meta_url = f"https://api.github.com/repos/{ref.owner}/{ref.repo}"
        meta = fetch(meta_url, timeout, _auth_headers(meta_url, token))
        if meta.status == 404:
            raise AuditDenied("repository not found or not public")
        if meta.status == 403:
            raise AuditDenied("repository not accessible (private or rate-limited)")
        if meta.status != 200:
            raise AuditDenied(f"repository metadata unavailable (HTTP {meta.status})")
        try:
            info = json.loads(meta.body.decode("utf-8"))
        except Exception:
            raise AuditDenied("invalid metadata response") from None
        default_branch = info.get("default_branch")
        if (not isinstance(default_branch, str) or not default_branch
                or not _BRANCH_RE.match(default_branch) or ".." in default_branch):
            raise AuditDenied("could not determine a safe default branch")

        tar_url = (f"https://codeload.github.com/{ref.owner}/{ref.repo}/"
                   f"tar.gz/refs/heads/{default_branch}")
        resp = fetch(tar_url, timeout, _auth_headers(tar_url, token))
        if resp.status != 200:
            raise AuditDenied(f"repository archive unavailable (HTTP {resp.status})")
        if len(resp.body) > limits.max_total_bytes:
            raise AuditDenied("repository archive too large")

        root, truncated = _extract_tarball(resp.body, limits)

        graph = Graph(":memory:")
        res = audit_repo(root, graph=graph, max_files=limits.max_files)

        report = DeepReport(owner=ref.owner, repo=ref.repo, ref=default_branch)
        report.files_scanned = res.files_scanned
        report.bytes_scanned = res.bytes_scanned
        report.languages = dict(res.languages)
        report.modules = res.modules
        report.entrypoints = list(res.entrypoints)
        report.truncated = truncated

        # top-imported modules (destinations of "imports" edges, by count)
        top = []
        for dst, count in graph.hubs(_MAX_TOP_IMPORTS):
            if dst.startswith("py:"):
                top.append((dst[3:], count))
            elif dst.startswith("pkg:"):
                top.append((dst[4:], count))
            else:
                top.append((dst, count))
        report.top_imports = top[:_MAX_TOP_IMPORTS]

        # import cycles over project files
        files = _walk_code_files(root)
        report.cycles = _find_cycles(_import_edges(root, files))

        _metadata_scan(root, report)

        cache: dict = {}
        ev = []
        for f in res.findings[:limits.max_findings]:
            e = _to_evidence(root, f, cache)
            if e is not None:
                ev.append(e)
        if len(res.findings) > limits.max_findings:
            report.truncated = True
        report.findings = ev
        report.manifest_root = manifest_root(ev)
        return report
    except AuditDenied:
        raise
    except safe_fetch.AccessDenied as e:
        raise AuditDenied("fetch denied") from e
    except Exception:
        raise AuditDenied("deep audit failed") from None
    finally:
        if root is not None:
            shutil.rmtree(root, ignore_errors=True)


def _walk_code_files(root: str) -> list[str]:
    out: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames
                       if d not in _SKIP_SET and not d.startswith(".venv")]
        for fn in filenames:
            if os.path.splitext(fn)[1].lower() in CODE_EXT:
                out.append(os.path.relpath(os.path.join(dirpath, fn), root)
                           .replace(os.sep, "/"))
    return out
