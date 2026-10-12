"""Master STATIC analysis engine — any language, any tree, offline.

Given a local directory (an extracted repo, an unpacked archive, a checkout),
produce a deep, evidence-carrying report: secrets, language-specific risk
packs, supply-chain signals, architecture metrics, complexity hotspots,
manifests/SBOM, licenses, CI/IaC inventory and test inventory.

Hard rules, enforced by construction:
  * Nothing is executed. Files are opened and read as text only.
  * No network. No credentials. No wallet/payment imports.
  * Every finding carries ``path:line``, a secret-MASKED snippet and sha256
    receipts for the file and the snippet.
  * Output is deterministic and bounded by `AnalysisLimits`.

The rule data lives in `devin.polyglot`; severity mapping is shared with
`architect.audit` so DEVin scores the same way everywhere.
"""
from __future__ import annotations

import io
import json
import os
import re
from dataclasses import dataclass, field

from architect.audit import _EXAMPLE, _mask, _sev
from architect.evidence import (Evidence, manifest_root, severity_counts,
                                sha256_bytes)

from . import polyglot as pg

_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_DOC_EXTS = frozenset({".md", ".markdown", ".rst", ".txt", ".adoc", ".org"})
_NON_CODE_LANGS = {"JSON", "JSON5", "YAML", "INI", "Dotenv", "TOML", "XML",
                   "Plist", "Properties", "Text", "Markdown", "Config",
                   "Protobuf", "GraphQL", "Thrift", "Template"}
_SNIPPET_MAX = 200
_DEPS_PER_MANIFEST = 25
_MAX_HOTSPOTS = 12
_MAX_KEY_FILES = 40
_MAX_LICENSES = 10

_MANIFEST_BY_BASENAME = {k.lower(): v for k, v in pg.MANIFESTS.items()
                         if "*" not in k}
_MANIFEST_GLOBS = [(k, v) for k, v in pg.MANIFESTS.items() if "*" in k]


@dataclass(frozen=True)
class AnalysisLimits:
    """Hard bounds — safety limits, not preferences."""
    max_files: int = 1500
    max_file_bytes: int = 300_000
    max_total_bytes: int = 24_000_000
    max_findings: int = 120
    max_hotspots: int = _MAX_HOTSPOTS


@dataclass
class AnalysisReport:
    root: str = ""
    mode: str = "static-only"
    files_scanned: int = 0
    files_skipped: int = 0
    bytes_scanned: int = 0
    loc: int = 0
    languages: dict = field(default_factory=dict)
    entrypoints: list = field(default_factory=list)
    manifests: dict = field(default_factory=dict)     # name -> [dep, ...]
    lockfiles: list = field(default_factory=list)
    sbom: list = field(default_factory=list)          # [(ecosystem, name, ver)]
    licenses: list = field(default_factory=list)
    ci: list = field(default_factory=list)
    iac: list = field(default_factory=list)
    tests: list = field(default_factory=list)
    key_files: list = field(default_factory=list)
    hotspots: list = field(default_factory=list)      # [(path, score, note)]
    todos: int = 0
    fixmes: int = 0
    suppressions: int = 0
    findings: list = field(default_factory=list)      # Evidence
    notes: list = field(default_factory=list)         # project-level signals
    truncated: bool = False
    manifest_root: str = ""

    def severity_counts(self) -> dict:
        return severity_counts(self.findings)

    def summary(self) -> dict:
        return {
            "files": self.files_scanned,
            "loc": self.loc,
            "languages": len(self.languages),
            "findings": self.severity_counts(),
            "sbom": len(self.sbom),
        }


# ── masking (secrets must never reach a report, chat, or log) ──────────────

_SECRET_PAT = [(name, re.compile(pat))
               for name, pat, _score in pg.SECRET_RULES]
_SECRET_PAT += [("common_secret", re.compile(pat))
                for name, pat, _score, _w in pg.RISK_COMMON
                if name in ("bearer_literal", "basic_auth_url", "jwt")]


def mask_line(line: str) -> str:
    """Replace every secret-shaped token on a line with its masked form."""
    out = line
    for _name, pat in _SECRET_PAT:
        for m in pat.finditer(out):
            tok = m.group(0)
            if _EXAMPLE.search(tok):
                continue
            out = out.replace(tok, _mask(tok), 1)
    return out.strip()[:_SNIPPET_MAX]


def _line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def _finding(rule, severity, rel, line, lines, fhash, detail) -> Evidence | None:
    if line < 1 or line > len(lines):
        return None
    snippet = mask_line(lines[line - 1])
    return Evidence(rule=rule, severity=severity, path=rel, line=line,
                    snippet=snippet, file_sha256=fhash,
                    snippet_sha256=sha256_bytes(snippet.encode()),
                    detail=detail or "")


# ── complexity / structure heuristics (structural, not a parser) ───────────

_DECISION = re.compile(
    r"\b(?:if|else\s+if|elif|for|while|case|when|catch|except|switch|match|"
    r"&&|\|\||guard|rescue)\b|[?]{1}\s*[^:]*:")
_PY_DEF = re.compile(r"^(?P<ind>\s*)(?:async\s+)?def\s+(?P<name>\w+)", re.M)
_BRACE_OPEN, _BRACE_CLOSE = "{", "}"


def _py_functions(text: str) -> list[tuple[str, int, int]]:
    """(name, line, length) for Python defs, measured by indentation."""
    out = []
    lines = text.splitlines()
    marks = [(m.start(), m.group("ind"), m.group("name"))
             for m in _PY_DEF.finditer(text)]
    if not marks:
        return out
    # map char offset -> line index
    starts = [0]
    for ln in lines:
        starts.append(starts[-1] + len(ln) + 1)
    import bisect
    for i, (pos, ind, name) in enumerate(marks):
        ln = bisect.bisect_right(starts, pos) - 1
        end = len(lines)
        if i + 1 < len(marks):
            nxt = bisect.bisect_right(starts, marks[i + 1][0]) - 1
            end = nxt
        else:
            for j in range(ln + 1, len(lines)):
                s = lines[j]
                if not s.strip():
                    continue
                cur = len(s) - len(s.lstrip())
                if cur <= len(ind):
                    end = j
                    break
        out.append((name, ln + 1, max(0, end - ln)))
    return out


def _brace_depth(text: str) -> int:
    depth = mx = 0
    for ch in text:
        if ch == _BRACE_OPEN:
            depth += 1
            mx = max(mx, depth)
        elif ch == _BRACE_CLOSE:
            depth = max(0, depth - 1)
    return mx


# ── manifest parsing (SBOM, many ecosystems) ───────────────────────────────

_REQ_LINE = re.compile(r"^\s*([A-Za-z0-9_.\-\[\]]+)\s*(?:==|>=|<=|~=|!=|>|<)\s*([^\s;#]+)")
_LOCK_PIN = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*==\s*([^\s;#]+)")
_TOML_DEP = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*=\s*[\"']([^\"']+)[\"']")
_GO_REQ = re.compile(r"^\s*([a-zA-Z0-9./\-]+)\s+v([0-9][^\s]*)")
_CARGO_DEP = re.compile(r"^\s*([A-Za-z0-9_\-]+)\s*=\s*(?:\{[^}]*version\s*=\s*[\"']([^\"']+)[\"']|[\"']([^\"']+)[\"'])")
_POM_DEP = re.compile(r"<artifactId>\s*([^<]+)\s*</artifactId>")
_POM_VER = re.compile(r"<version>\s*([^<]+)\s*</version>")
_GEM = re.compile(r"^\s*gem\s+[\"']([^\"']+)[\"'](?:\s*,\s*[\"']([^\"']+)[\"'])?")
_GRADLE = re.compile(r"^\s*(?:implementation|api|compileOnly|runtimeOnly|testImplementation|classpath)\s*\(?\s*[\"']([^\"':]+):([^\"':]+):([^\"']+)[\"']")
_CSPROJ = re.compile(r"<PackageReference\s+[^>]*Include=\"([^\"]+)\"[^>]*Version=\"([^\"]+)\"")
_PUBSPEC = re.compile(r"^\s{2,}([a-zA-Z0-9_\-]+):\s*(?:\^|>=)?\s*([0-9][^\s]*)?")


def _deps_pypi(text: str) -> list:
    out = []
    for ln in text.splitlines():
        m = _REQ_LINE.match(ln) or _LOCK_PIN.match(ln)
        if m:
            out.append(f"{m.group(1)}=={m.group(2)}")
        elif re.match(r"^\s*[A-Za-z0-9_.\-]+\s*$", ln) and "name" not in ln:
            continue
        if len(out) >= _DEPS_PER_MANIFEST:
            break
    return out


def _deps_npm(text: str) -> list:
    try:
        j = json.loads(text)
    except Exception:
        return []
    out = []
    for section in ("dependencies", "devDependencies", "peerDependencies",
                    "optionalDependencies"):
        for name, ver in (j.get(section) or {}).items():
            out.append(f"{name}@{ver}")
            if len(out) >= _DEPS_PER_MANIFEST:
                return out
    return out


def _deps_go(text: str) -> list:
    out = []
    for ln in text.splitlines():
        m = _GO_REQ.match(ln.strip().lstrip("require").strip() if ln.strip().startswith("require") else ln)
        if m:
            out.append(f"{m.group(1)}@{m.group(2)}")
        if len(out) >= _DEPS_PER_MANIFEST:
            break
    return out


def _deps_cargo(text: str) -> list:
    out, in_deps = [], False
    for ln in text.splitlines():
        s = ln.strip()
        if s.startswith("[") and s.endswith("]"):
            in_deps = s.strip("[]").strip().lower() in (
                "dependencies", "dev-dependencies", "build-dependencies")
            continue
        if in_deps and s and not s.startswith("#"):
            m = _CARGO_DEP.match(ln)
            if m:
                out.append(f"{m.group(1)}@{m.group(2) or m.group(3) or '*'}")
        if len(out) >= _DEPS_PER_MANIFEST:
            break
    return out


def _deps_pom(text: str) -> list:
    arts = _POM_DEP.findall(text)[:_DEPS_PER_MANIFEST]
    vers = _POM_VER.findall(text)[:_DEPS_PER_MANIFEST]
    out = []
    for i, a in enumerate(arts):
        v = vers[i] if i < len(vers) else "*"
        out.append(f"{a}@{v}")
    return out


def _deps_gem(text: str) -> list:
    out = []
    for ln in text.splitlines():
        m = _GEM.match(ln)
        if m:
            out.append(f"{m.group(1)}@{m.group(2) or '*'}")
        if len(out) >= _DEPS_PER_MANIFEST:
            break
    return out


def _deps_gradle(text: str) -> list:
    out = []
    for ln in text.splitlines():
        m = _GRADLE.match(ln)
        if m:
            out.append(f"{m.group(1)}:{m.group(2)}@{m.group(3)}")
        if len(out) >= _DEPS_PER_MANIFEST:
            break
    return out


def _deps_csproj(text: str) -> list:
    return [f"{a}@{v}" for a, v in _CSPROJ.findall(text)[:_DEPS_PER_MANIFEST]]


def _deps_composer(text: str) -> list:
    try:
        j = json.loads(text)
    except Exception:
        return []
    out = []
    for section in ("require", "require-dev"):
        for name, ver in (j.get(section) or {}).items():
            if name == "php":
                continue
            out.append(f"{name}@{ver}")
            if len(out) >= _DEPS_PER_MANIFEST:
                return out
    return out


def _deps_pubspec(text: str) -> list:
    out, in_deps = [], False
    for ln in text.splitlines():
        if re.match(r"^[a-zA-Z_]+:", ln):
            in_deps = ln.strip().startswith(("dependencies:", "dev_dependencies:"))
            continue
        if in_deps:
            m = _PUBSPEC.match(ln)
            if m:
                out.append(f"{m.group(1)}@{m.group(2) or '*'}")
        if len(out) >= _DEPS_PER_MANIFEST:
            break
    return out


def _deps_toml(text: str) -> list:
    out = []
    for ln in text.splitlines():
        m = _TOML_DEP.match(ln)
        if m and m.group(1) not in ("name", "version", "description", "edition"):
            out.append(f"{m.group(1)}@{m.group(2)}")
        if len(out) >= _DEPS_PER_MANIFEST:
            break
    return out


_DEPS_BY_ECO = {
    "pypi": _deps_pypi, "conda": _deps_pypi, "npm": _deps_npm,
    "deno": _deps_npm, "go": _deps_go, "cargo": _deps_cargo,
    "maven": _deps_pom, "gradle": _deps_gradle, "sbt": _deps_toml,
    "rubygems": _deps_gem, "composer": _deps_composer, "nuget": _deps_csproj,
    "pub": _deps_pubspec, "swift": _deps_toml, "hex": _deps_toml,
    "julia": _deps_toml, "hackage": _deps_toml, "cmake": _deps_toml,
    "conan": _deps_toml, "vcpkg": _deps_npm, "clojure": _deps_toml,
    "cocoapods": _deps_gem, "cpan": _deps_gem, "runtime": _deps_toml,
}


def _split_dep(dep: str) -> tuple[str, str]:
    """Split "name@ver" / "name==ver" into (name, version).

    Scoped packages (@scope/pkg@1.2.3) must split on the LAST '@', not the
    first, or the scope is lost and the name comes out empty.
    """
    if "==" in dep:
        name, _, ver = dep.partition("==")
        return name.strip(), (ver.strip() or "*")
    if "@" in dep[1:]:
        name, ver = dep.rsplit("@", 1)
        return name.strip(), (ver.strip() or "*")
    return dep.strip(), "*"


def _manifest_ecosystem(name: str) -> str | None:
    low = name.lower()
    eco = _MANIFEST_BY_BASENAME.get(low)
    if eco:
        return eco
    for glob, e in _MANIFEST_GLOBS:
        if low.endswith(glob.replace("*", "")):
            return e
    return None


def _parse_manifest(name: str, text: str) -> tuple[str, list]:
    eco = _manifest_ecosystem(name) or "unknown"
    parser = _DEPS_BY_ECO.get(eco)
    deps = parser(text) if parser else []
    return eco, deps


# ── file classification ────────────────────────────────────────────────────

def _is_test(rel: str) -> bool:
    base = rel.rsplit("/", 1)[-1]
    return any(p.search(rel) or p.search(base) for p in pg.TEST_PATTERNS)


def _is_ci(rel: str) -> bool:
    return any(p.search(rel) for p in pg.CI_PATTERNS)


def _is_iac(rel: str) -> bool:
    return any(p.search(rel) for p in pg.IAC_PATTERNS)


def _read(path: str, cap: int) -> str | None:
    try:
        with open(path, "rb") as fh:
            raw = fh.read(cap + 1)
    except OSError:
        return None
    if len(raw) > cap:
        return None
    if b"\x00" in raw[:4096]:
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return None


# ── the engine ─────────────────────────────────────────────────────────────

def analyze_tree(root: str, limits: AnalysisLimits | None = None,
                 max_files: int | None = None) -> AnalysisReport:
    """Statically analyze every readable file under `root`. Never executes."""
    limits = limits or AnalysisLimits()
    if max_files is not None:
        limits = AnalysisLimits(max_files=max_files,
                                max_file_bytes=limits.max_file_bytes,
                                max_total_bytes=limits.max_total_bytes,
                                max_findings=limits.max_findings)
    rep = AnalysisReport(root=root)
    if not os.path.isdir(root):
        return rep

    findings: list[Evidence] = []
    hotspot_raw: list[tuple[int, str, str]] = []
    file_hashes: list[str] = []
    total = 0

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames
                       if d not in pg_skip_dirs() and not d.startswith(".venv")]
        for fn in sorted(filenames):
            if rep.files_scanned >= limits.max_files:
                rep.truncated = True
                break
            rel = os.path.relpath(os.path.join(dirpath, fn), root).replace(os.sep, "/")
            ext = os.path.splitext(fn)[1].lower()
            lang = pg.language_of(rel)
            low = fn.lower()
            readable = (ext in pg.CODE_EXTS or ext in pg.SECRET_ONLY_EXTS
                        or fn in pg.LANG_BY_NAME or lang is not None
                        or _is_ci(rel) or _is_iac(rel)
                        or bool(pg.LICENSE_FILES.match(fn))
                        or low in pg.LOCKFILES
                        or low in pg.SECRET_ONLY_NAMES
                        or _manifest_ecosystem(fn) is not None)
            if not readable:
                rep.files_skipped += 1
                continue
            path = os.path.join(dirpath, fn)
            try:
                size = os.path.getsize(path)
            except OSError:
                continue
            if size > limits.max_file_bytes or total + size > limits.max_total_bytes:
                rep.truncated = True
                rep.files_skipped += 1
                continue
            text = _read(path, limits.max_file_bytes)
            if text is None:
                rep.files_skipped += 1
                continue
            total += size
            rep.files_scanned += 1
            rep.bytes_scanned += len(text)
            try:
                with open(path, "rb") as fh:
                    fhash = sha256_bytes(fh.read())
            except OSError:
                continue
            file_hashes.append(f"{rel}:{fhash}")
            lines = text.splitlines()
            rep.loc += sum(1 for ln in lines if ln.strip())

            if lang:
                rep.languages[lang] = rep.languages.get(lang, 0) + 1

            # inventory
            base = fn.lower()
            if base in pg.LOCKFILES:
                rep.lockfiles.append(rel)
            if _manifest_ecosystem(fn):
                eco, deps = _parse_manifest(fn, text)
                rep.manifests[rel] = deps
                for d in deps:
                    rep.sbom.append((eco,) + _split_dep(d))
            if pg.LICENSE_FILES.match(fn) and len(rep.licenses) < _MAX_LICENSES:
                spdx = "unknown"
                for pat, tag in pg.LICENSE_SPDX_HINTS:
                    if pat.search(text):
                        spdx = tag
                        break
                rep.licenses.append(f"{rel} ({spdx})")
            if _is_ci(rel):
                rep.ci.append(rel)
            if _is_iac(rel):
                rep.iac.append(rel)
            if _is_test(rel):
                rep.tests.append(rel)
            if (len(rep.key_files) < _MAX_KEY_FILES and lang
                    and not _is_test(rel)
                    and (base in pg.LANG_BY_NAME or base in
                         ("requirements.txt", "package.json", "go.mod",
                          "Cargo.toml", "pom.xml", "Dockerfile", "Makefile",
                          "pyproject.toml", "composer.json", "Gemfile"))):
                rep.key_files.append(rel)

            rep.todos += len(re.findall(r"\bTODO\b", text))
            rep.fixmes += len(re.findall(r"\bFIXME\b", text))
            rep.suppressions += len(re.findall(
                r"noqa|eslint-disable|@ts-ignore|@ts-nocheck|# type: ignore|"
                r"nolint|SuppressWarnings|@Suppress", text))

            for pat, lang_tag in pg.ENTRYPOINT_RULES:
                if lang_tag == lang and re.search(pat, text):
                    rep.entrypoints.append(rel)
                    break

            # ── findings: secrets ───────────────────────────────────────
            for name, pat, score in pg.SECRET_RULES:
                for m in re.finditer(pat, text):
                    if _EXAMPLE.search(m.group(0)):
                        continue
                    f = _finding(f"secret:{name}", _sev(score), rel,
                                 _line_of(text, m.start()), lines, fhash,
                                 _mask(m.group(0)))
                    if f:
                        findings.append(f)

            # Documentation and log files are scanned for SECRETS only: their
            # prose trips code-shaped rules (http:// in a changelog, an IP in
            # release notes) and would bury the real signal in noise.
            if ext in _DOC_EXTS:
                continue

            # ── findings: risk (common + language pack) ─────────────────
            for name, pat, score, why in pg.RISK_COMMON:
                for m in re.finditer(pat, text):
                    f = _finding(f"risk:{name}", _sev(score), rel,
                                 _line_of(text, m.start()), lines, fhash, why)
                    if f:
                        findings.append(f)
            for name, pat, score, why in pg.lang_pack(lang or ""):
                for m in re.finditer(pat, text):
                    f = _finding(f"risk:{name}", _sev(score), rel,
                                 _line_of(text, m.start()), lines, fhash, why)
                    if f:
                        findings.append(f)

            # ── findings: supply chain (install-time / CI signals) ──────
            for pat, score, why in pg.SUPPLY_CHAIN_HINTS:
                for m in re.finditer(pat, text):
                    f = _finding("supply:" + re.sub(r"\W+", "_", why)[:40],
                                 _sev(score), rel, _line_of(text, m.start()),
                                 lines, fhash, why)
                    if f:
                        findings.append(f)

            # ── complexity hotspot scoring ──────────────────────────────
            decisions = len(_DECISION.findall(text))
            depth = _brace_depth(text) if lang != "Python" else 0
            score = decisions + depth * 2
            if lang == "Python":
                for name, ln, length in _py_functions(text):
                    if length >= 60:
                        score += 10
            if score > 0 and lang not in _NON_CODE_LANGS:
                hotspot_raw.append(
                    (score, rel, f"{decisions} decision points, depth {depth}"))

    # ── derived signals ────────────────────────────────────────────────────
    rep.sbom = sorted(set(rep.sbom))[:400]
    rep.entrypoints = sorted(set(rep.entrypoints))[:40]
    rep.licenses = sorted(set(rep.licenses))
    rep.ci = sorted(set(rep.ci))[:40]
    rep.iac = sorted(set(rep.iac))[:60]
    rep.tests = sorted(set(rep.tests))[:60]
    rep.lockfiles = sorted(set(rep.lockfiles))[:40]

    # Project-level signals live in `notes`, NOT in `findings`: a finding must
    # always carry a real path:line and sha256 receipts, and there is no file
    # to receipt for "this repo has no lockfile".
    langs_present = set(rep.languages)
    if ({"JavaScript", "TypeScript"} & langs_present) and not any(
            l.endswith(("package-lock.json", "yarn.lock", "pnpm-lock.yaml",
                        "npm-shrinkwrap.json")) for l in rep.lockfiles):
        rep.notes.append("node deps present, no lockfile committed "
                         "(unreproducible installs)")
    if "Python" in langs_present and not any(
            l.endswith(("poetry.lock", "Pipfile.lock", "uv.lock", "pdm.lock"))
            for l in rep.lockfiles):
        rep.notes.append("python deps present, no pinned lockfile "
                         "(version ranges, not pins)")
    if not rep.licenses:
        rep.notes.append("no LICENSE/COPYING file found "
                         "(redistribution terms unclear)")
    if not rep.tests:
        rep.notes.append("no test files detected")
    if not rep.ci:
        rep.notes.append("no CI workflow detected")
    for rel in rep.iac:
        if rel.lower().endswith((".env", ".envrc")):
            rep.notes.append(f"{rel}: dotenv-style file in the tree — verify no "
                             "live credentials are committed")
    if rep.suppressions > 20:
        rep.notes.append(f"{rep.suppressions} lint/type suppressions "
                         "(disabled checks can hide defects)")

    # ── order, cap, receipts ───────────────────────────────────────────────
    findings.sort(key=lambda e: (_SEV_RANK.get(e.severity, 9), e.path, e.line,
                                 e.rule))
    if len(findings) > limits.max_findings:
        rep.truncated = True
        # never drop a critical: sort already put them first
        findings = findings[:limits.max_findings]
    rep.findings = findings
    rep.manifest_root = manifest_root(findings)

    hotspot_raw.sort(key=lambda t: (-t[0], t[1]))
    rep.hotspots = [(p, s, n) for s, p, n in hotspot_raw[:limits.max_hotspots]]
    return rep


_SKIP_DIRS = {
    ".git", "node_modules", ".next", "dist", "build", "__pycache__",
    ".venv", "venv", ".venv-ml", "vendor", "target", ".cache",
    "site-packages", "coverage", ".mypy_cache", ".pytest_cache", ".tox",
    ".idea", ".vscode", "bower_components", ".gradle", ".terraform",
    "Pods", "DerivedData", ".dart_tool", "obj", "bin",
}


def pg_skip_dirs() -> set:
    return _SKIP_DIRS


# ── archive intake (traversal-safe, no execution, bounded) ─────────────────

def safe_member(member_name: str) -> str | None:
    """Validate an archive member path WITHOUT rewriting it.

    This is the canonical guard: normalize what is safe to normalize, refuse
    everything else. It does NOT strip a leading directory — callers that know
    their archive has a wrapper root ask for that explicitly (`_safe_rel` with
    `strip_root=True`), because silently stripping the first component turns
    `src/app.py` into `app.py`: data loss and path collisions.
    """
    name = (member_name or "").replace("\\", "/")
    if name.startswith("./"):
        name = name[2:]
    if not name or name.startswith("/") or "\\" in name:
        return None
    parts = name.split("/")
    if any(seg in ("", ".", "..") for seg in parts):
        return None
    return name


def _rel_path(member_name: str) -> str:
    """Strip the single wrapping directory GitHub codeload tarballs add."""
    rel = safe_member(member_name)
    if rel is None:
        return ""
    parts = rel.split("/")
    if len(parts) > 1 and parts[0]:
        return "/".join(parts[1:])
    return rel


def _safe_rel(member_name: str, strip_root: bool = True) -> str | None:
    """Safe member path; strips one wrapper dir by default (GitHub layout)."""
    if strip_root:
        rel = _rel_path(member_name)
    else:
        rel = safe_member(member_name)
    if not rel or rel.startswith("/") or "\\" in rel:
        return None
    parts = rel.split("/")
    if any(seg in ("", ".", "..") for seg in parts):
        return None
    return rel


def _skip_path(rel: str) -> bool:
    if not rel:
        return True
    return any(seg in _SKIP_DIRS or seg.startswith(".venv")
               for seg in rel.split("/"))


def extract_zip(data: bytes, limits: AnalysisLimits | None = None,
                into: str | None = None, strip_root: bool = False
                ) -> tuple[str | None, bool]:
    """Extract a ZIP into a fresh temp dir, traversal-safe. (root, trunc).

    Same guarantees as `extract_tarball`: symlinks and traversal names are
    refused, caps are enforced, nothing is executed. `strip_root` defaults to
    False because an uploaded archive is the user's own layout, not GitHub's.
    """
    import tempfile
    import zipfile
    limits = limits or AnalysisLimits()
    root = into or tempfile.mkdtemp(prefix="devin-zip-")
    truncated = False
    total = files = 0
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except Exception:
        if into is None:
            import shutil as _sh
            _sh.rmtree(root, ignore_errors=True)
        return None, False
    try:
        for info in zf.infolist():
            if files >= limits.max_files or total >= limits.max_total_bytes:
                truncated = True
                break
            # is_dir() entries carry no data; anything with an unusual mode or a
            # symlink bit is skipped rather than materialized.
            if info.is_dir() or (info.external_attr >> 16) & 0o170000 == 0o120000:
                continue
            rel = _safe_rel(info.filename, strip_root=strip_root)
            if rel is None or _skip_path(rel):
                continue
            if info.file_size > limits.max_file_bytes:
                truncated = True
                continue
            try:
                raw = zf.read(info)               # zipfile checks CRC
            except Exception:
                truncated = True
                continue
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
    except Exception:
        truncated = True
    finally:
        zf.close()
    return root, truncated


def extract_tarball(data: bytes, limits: AnalysisLimits | None = None,
                    into: str | None = None, strip_root: bool = True
                    ) -> tuple[str | None, bool]:
    """Extract a gzipped tarball into a fresh temp dir. Returns (root, trunc).

    Skips symlinks/hardlinks and traversal names, and enforces the file and
    byte caps so a hostile archive cannot fill the disk. Nothing is executed.
    `strip_root=True` (default) drops the wrapper directory GitHub adds; pass
    False for an archive that is the user's own layout.
    """
    import tarfile
    import tempfile
    limits = limits or AnalysisLimits()
    root = into or tempfile.mkdtemp(prefix="devin-tree-")
    truncated = False
    total = files = 0
    try:
        tf = tarfile.open(fileobj=io.BytesIO(data), mode="r:gz")
    except Exception:
        if into is None:
            import shutil as _sh
            _sh.rmtree(root, ignore_errors=True)
        return None, False
    try:
        for member in tf:
            if files >= limits.max_files or total >= limits.max_total_bytes:
                truncated = True
                break
            if not member.isfile() or member.issym() or member.islnk():
                continue
            rel = _safe_rel(member.name, strip_root=strip_root)
            if rel is None or _skip_path(rel):
                continue
            if member.size > limits.max_file_bytes:
                truncated = True
                continue
            fh = tf.extractfile(member)
            if fh is None:
                continue
            raw = fh.read(limits.max_file_bytes + 1)
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
    except Exception:
        truncated = True
    finally:
        tf.close()
    return root, truncated


def analyze_tarball(data: bytes, limits: AnalysisLimits | None = None
                    ) -> AnalysisReport:
    """Extract + analyze an archive in one shot, cleaning up the temp tree."""
    import shutil as _sh
    limits = limits or AnalysisLimits()
    root, _trunc = extract_tarball(data, limits)
    if root is None:
        rep = AnalysisReport()
        rep.truncated = True
        return rep
    try:
        rep = analyze_tree(root, limits)
        return rep
    finally:
        _sh.rmtree(root, ignore_errors=True)
