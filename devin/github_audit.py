"""Safe, bounded, read-only STATIC inspection of a PUBLIC GitHub repository.

Scope is exactly ``https://github.com/<owner>/<repo>`` — nothing else. The repo
is fetched over a host-allowlisted, SSRF-pinned, public-IP-only transport and
scanned with regex rules ONLY. Nothing is executed: no shell, no subprocess, no
eval, no LLM prompt execution, no x402 spend, no wallet access. Every finding
carries ``path:line``, a (secret-masked) snippet, and sha256 receipts for the
file and the snippet; the whole result is labelled ``static-only``.
"""
from __future__ import annotations

import io
import json
import re
import tarfile
import urllib.parse
from dataclasses import dataclass, field

from architect import safe_fetch
from architect.audit import (CODE_EXT, SECRET_RULES, SKIP_DIRS, RISK_RULES,
                             _EXAMPLE, _mask, _range, _sev)
from architect.evidence import (Evidence, manifest_root, severity_counts,
                                sha256_bytes)

from .analysis import AnalysisLimits, analyze_tree, extract_tarball

_REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
_BRANCH_RE = re.compile(r"^[A-Za-z0-9._/-]+$")
_SNIPPET_MAX = 200
# The ONLY hosts a GitHub token may ever be sent to, and only as an
# Authorization header. Anything else (logs, errors, findings) must stay clean.
_TOKEN_HOSTS = frozenset({"api.github.com", "codeload.github.com"})


def _auth_headers(url: str, token: str | None) -> dict | None:
    """Build the Authorization header for a GitHub fetch, host-gated.

    Returns None (no header) when there is no token or when the URL's host is
    not one of the two token-accepting hosts. This is the single choke point
    that guarantees a token is never sent to an unexpected host.
    """
    if not token:
        return None
    host = (urllib.parse.urlsplit(url).hostname or "").lower()
    if host in _TOKEN_HOSTS:
        return {"Authorization": f"Bearer {token}"}
    return None


class AuditDenied(Exception):
    """A target or fetch was refused (not public, unsafe, too large, etc.)."""


@dataclass(frozen=True)
class RepoRef:
    owner: str
    repo: str


@dataclass(frozen=True)
class AuditLimits:
    max_files: int = 200
    max_file_bytes: int = 200_000
    max_total_bytes: int = 4_000_000
    max_findings: int = 50


@dataclass
class AuditOutcome:
    owner: str
    repo: str
    ref: str
    mode: str = "static-only"
    files_scanned: int = 0
    bytes_scanned: int = 0
    findings: list = field(default_factory=list)
    truncated: bool = False
    manifest_root: str = ""
    # polyglot engine additions (any language)
    languages: dict = field(default_factory=dict)
    loc: int = 0
    sbom: list = field(default_factory=list)
    hotspots: list = field(default_factory=list)
    licenses: list = field(default_factory=list)
    notes: list = field(default_factory=list)
    engine: str = "architect"

    def severity_counts(self) -> dict:
        return severity_counts(self.findings)


# ── URL parsing ────────────────────────────────────────────────────────────

def parse_repo_url(url: str) -> RepoRef:
    if not isinstance(url, str) or not url.strip():
        raise AuditDenied("empty URL")
    url = url.strip()
    if len(url) > 2048:
        raise AuditDenied("URL too long")
    p = urllib.parse.urlsplit(url)
    if p.scheme != "https":
        raise AuditDenied("only https allowed")
    if p.hostname is None or p.hostname.lower() != "github.com":
        raise AuditDenied("only public github.com repos allowed")
    if p.username or p.password or p.port or p.query or p.fragment:
        raise AuditDenied("URL must be a bare repo page")
    parts = [seg for seg in p.path.split("/") if seg]
    if len(parts) != 2:
        raise AuditDenied("URL must be github.com/<owner>/<repo>")
    owner, repo = parts
    if repo.endswith(".git"):
        repo = repo[:-4]
    if not _REPO_RE.match(owner) or not _REPO_RE.match(repo):
        raise AuditDenied("invalid owner or repo name")
    return RepoRef(owner, repo)


# ── tarball inspection ─────────────────────────────────────────────────────

def _rel_path(member_name: str) -> str:
    name = member_name.replace("\\", "/")
    if name.startswith("./"):
        name = name[2:]
    parts = name.split("/")
    # GitHub codeload tarballs wrap everything in a single top-level dir.
    if len(parts) > 1 and parts[0]:
        return "/".join(parts[1:])
    return name


def _skip_path(rel: str) -> bool:
    if not rel:
        return True
    parts = rel.split("/")
    return any(seg in SKIP_DIRS or seg.startswith(".venv") for seg in parts)


def _evidence_from_finding(root: str, f, cache: dict) -> Evidence | None:
    """Convert an `architect.audit.Finding` into masked, receipted Evidence."""
    import os as _os
    rel = f.path.replace(_os.sep, "/")
    if rel not in cache:
        try:
            with open(_os.path.join(root, rel), "rb") as fh:
                raw = fh.read()
        except OSError:
            cache[rel] = (None, [])
            return None
        cache[rel] = (sha256_bytes(raw),
                      raw.decode("utf-8", "replace").splitlines())
    fhash, lines = cache[rel]
    if not fhash or f.line < 1 or f.line > len(lines):
        return None
    snippet = _masked_snippet(lines[f.line - 1])
    return Evidence(rule=str(f.kind), severity=f.severity, path=rel,
                    line=f.line, snippet=snippet, file_sha256=fhash,
                    snippet_sha256=sha256_bytes(snippet.encode()),
                    detail=getattr(f, "detail", "") or "")


def inspect_tarball_full(data: bytes, owner: str, repo: str, ref: str,
                         limits: AuditLimits) -> AuditOutcome:
    """Full-polyglot static audit of an archive: architect rules + the
    any-language engine, merged, deduped, receipted. Nothing is executed."""
    import os as _os
    import shutil

    alimits = AnalysisLimits(max_files=limits.max_files,
                             max_file_bytes=limits.max_file_bytes,
                             max_total_bytes=limits.max_total_bytes,
                             max_findings=limits.max_findings)
    root, trunc = extract_tarball(data, alimits)
    if root is None:
        raise AuditDenied("not a readable archive")
    out = AuditOutcome(owner=owner, repo=repo, ref=ref, engine="polyglot")
    try:
        # 1. existing architect rule pack (back-compat rule names)
        try:
            from architect.audit import audit_repo
            from architect.graph import Graph
            res = audit_repo(root, graph=Graph(":memory:"),
                             max_files=limits.max_files)
            arch_findings = res.findings
            out.files_scanned = res.files_scanned
            out.bytes_scanned = res.bytes_scanned
        except Exception:
            arch_findings = []
        # 2. the polyglot engine (any language, big pack)
        rep = analyze_tree(root, alimits)

        cache: dict = {}
        merged: list = []
        seen: set = set()
        for f in arch_findings:
            e = _evidence_from_finding(root, f, cache)
            if e is None:
                continue
            key = (e.rule, e.path, e.line, e.snippet_sha256)
            if key in seen:
                continue
            seen.add(key)
            merged.append(e)
        for e in rep.findings:
            key = (e.rule, e.path, e.line, e.snippet_sha256)
            if key in seen:
                continue
            seen.add(key)
            merged.append(e)

        rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        merged.sort(key=lambda e: (rank.get(e.severity, 9), e.path, e.line))
        if len(merged) > limits.max_findings:
            trunc = True
            merged = merged[:limits.max_findings]
        out.findings = merged
        out.truncated = trunc or rep.truncated
        out.manifest_root = manifest_root(merged)
        out.files_scanned = max(out.files_scanned, rep.files_scanned)
        out.bytes_scanned = max(out.bytes_scanned, rep.bytes_scanned)
        out.languages = dict(rep.languages)
        out.loc = rep.loc
        out.sbom = list(rep.sbom)
        out.hotspots = list(rep.hotspots)
        out.licenses = list(rep.licenses)
        out.notes = list(rep.notes)
        return out
    finally:
        shutil.rmtree(root, ignore_errors=True)


def _masked_snippet(line_text: str) -> str:
    """Mask any secret-looking tokens in a line so secrets never reach chat."""
    out = line_text
    for _rule, pat, _score in SECRET_RULES:
        for m in re.finditer(pat, out):
            if not _EXAMPLE.search(m.group(0)):
                out = out.replace(m.group(0), _mask(m.group(0)), 1)
    return out.strip()[:_SNIPPET_MAX]


def _finding(rule: str, kind: str, severity: str, rel: str, line: int,
             lines: list, fhash: str, detail: str) -> Evidence | None:
    if line < 1 or line > len(lines):
        return None
    snippet = _masked_snippet(lines[line - 1])
    return Evidence(
        rule=f"{kind}:{rule}", severity=severity, path=rel, line=line,
        snippet=snippet, file_sha256=fhash,
        snippet_sha256=sha256_bytes(snippet.encode()), detail=detail or "")


def inspect_tarball(data: bytes, owner: str, repo: str, ref: str,
                    limits: AuditLimits) -> AuditOutcome:
    out = AuditOutcome(owner=owner, repo=repo, ref=ref)
    file_hashes: list[str] = []
    try:
        tf = tarfile.open(fileobj=io.BytesIO(data), mode="r:gz")
    except Exception as e:
        raise AuditDenied("not a readable archive") from e
    try:
        for member in tf:
            if out.files_scanned >= limits.max_files:
                out.truncated = True
                break
            if not member.isfile():
                continue
            if member.issym() or member.islnk():
                continue
            rel = _rel_path(member.name)
            if _skip_path(rel):
                continue
            ext = ("." + rel.rsplit(".", 1)[1].lower()) if "." in rel else ""
            if ext not in CODE_EXT:
                continue
            if member.size > limits.max_file_bytes:
                out.truncated = True
                continue
            try:
                f = tf.extractfile(member)
                if f is None:
                    continue
                raw = f.read(limits.max_file_bytes + 1)
            except Exception:
                continue
            if len(raw) > limits.max_file_bytes:
                out.truncated = True
                continue
            if out.bytes_scanned + len(raw) > limits.max_total_bytes:
                out.truncated = True
                break
            if b"\x00" in raw[:4096]:        # binary blob — not code text
                continue
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError:
                continue
            out.files_scanned += 1
            out.bytes_scanned += len(raw)
            fhash = sha256_bytes(raw)
            file_hashes.append(f"{rel}:{fhash}")
            lines = text.splitlines()

            for rule, pat, score in SECRET_RULES:
                for m in _range(text, pat):
                    line = text.count("\n", 0, m.start()) + 1
                    f = _finding(rule, "secret", _sev(score), rel, line, lines,
                                 fhash, _mask(m.group(0)))
                    if f is not None:
                        out.findings.append(f)
            for rule, pat, score, why in RISK_RULES:
                for m in _range(text, pat):
                    line = text.count("\n", 0, m.start()) + 1
                    f = _finding(rule, "risk", _sev(score), rel, line, lines,
                                 fhash, why)
                    if f is not None:
                        out.findings.append(f)

            if len(out.findings) >= limits.max_findings:
                out.truncated = True
                break
    finally:
        tf.close()

    out.findings = out.findings[:limits.max_findings]
    out.manifest_root = manifest_root(out.findings)
    return out


# ── orchestration ──────────────────────────────────────────────────────────

def audit_public_repo(url: str, fetch, limits: AuditLimits | None = None,
                      timeout: float = 60.0, token: str | None = None) -> AuditOutcome:
    """Fetch (metadata + tarball) and statically inspect a GitHub repo.

    `fetch(url, timeout, headers=None) -> Response` must return an object with
    `.status` and `.body` (bytes). `headers` is an optional dict of extra HTTP
    headers (used to carry the Authorization header for private repos). Any
    refusal becomes `AuditDenied`; unexpected errors are collapsed to a generic
    refusal (no internal detail leaks to chat).

    With a `token`, private repos become auditable — the token is sent ONLY as
    an Authorization header to api.github.com/codeload.github.com and never
    appears in any finding, report, or error string. Without a token, a private
    repo is a clear refusal (404/403 -> AuditDenied).
    """
    limits = limits or AuditLimits()
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
        return inspect_tarball_full(resp.body, ref.owner, ref.repo,
                                    default_branch, limits)
    except AuditDenied:
        raise
    except safe_fetch.AccessDenied as e:
        raise AuditDenied("fetch denied") from e
    except Exception:
        raise AuditDenied("audit failed") from None
