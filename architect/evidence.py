"""Evidence receipts — the rule that makes this product credible.

NO FINDING WITHOUT EVIDENCE. Every finding carries:

  * the file and its 1-indexed line
  * the actual source line (snippet), not a paraphrase
  * sha256 of the whole file as it was at audit time
  * sha256 of the snippet itself

That makes a report *re-verifiable*. `architect verify-report` re-hashes the tree
and confirms each finding still points at the bytes it claims. A report you can
check is a report you can act on; everything else is a sales document.

Design note: a file that changed since the audit is reported as STALE, not as a
false finding. The audit is bound to a revision — saying so is more honest than
either pretending it still applies or silently dropping it.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import os
from dataclasses import asdict, dataclass, field

VERSION = "0.3.0"
MAX_SNIPPET = 200


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


@dataclass
class Evidence:
    """One verifiable finding."""

    rule: str
    severity: str
    path: str            # repo-relative, forward slashes
    line: int            # 1-indexed
    snippet: str         # the literal source line
    file_sha256: str
    snippet_sha256: str
    detail: str = ""
    node: str = ""       # which swarm node produced it

    @property
    def receipt(self) -> str:
        """Short, stable id for this finding at this revision."""
        material = f"{self.rule}|{self.path}|{self.line}|{self.snippet_sha256}"
        return "sha256:" + hashlib.sha256(material.encode()).hexdigest()[:16]

    def to_dict(self) -> dict:
        d = asdict(self)
        d["receipt"] = self.receipt
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Evidence":
        d = {k: v for k, v in d.items() if k != "receipt"}
        return cls(**d)


def capture(root: str, rel_path: str, line: int, rule: str, severity: str,
            detail: str = "", node: str = "", lines: list | None = None,
            file_hash: str | None = None) -> Evidence | None:
    """Build an Evidence receipt for one finding.

    `lines` is the file's decoded line list; pass it when scanning many findings
    in one file so the file is only read once. Returns None if the line is out
    of range — a finding pointing at nothing is not evidence.
    """
    abspath = os.path.join(root, rel_path)
    if lines is None:
        try:
            with open(abspath, "r", encoding="utf-8", errors="replace") as fh:
                lines = fh.read().splitlines()
        except OSError:
            return None
    if line < 1 or line > len(lines):
        return None

    snippet = lines[line - 1].strip()[:MAX_SNIPPET]
    if file_hash is None:
        try:
            file_hash = sha256_file(abspath)
        except OSError:
            return None

    return Evidence(
        rule=rule,
        severity=severity,
        path=rel_path.replace(os.sep, "/"),
        line=line,
        snippet=snippet,
        file_sha256=file_hash,
        snippet_sha256=sha256_bytes(snippet.encode()),
        detail=detail,
        node=node,
    )


# ── report assembly ────────────────────────────────────────────────────────

def manifest_root(findings: list[Evidence]) -> str:
    """One hash committing to the whole set of findings, order-independent."""
    material = "\n".join(sorted(
        f"{f.path}:{f.line}:{f.snippet_sha256}" for f in findings))
    return sha256_bytes(material.encode())


def build_report(findings: list[Evidence], root: str, nodes: dict | None = None,
                 payments: list | None = None, duration: float = 0.0) -> dict:
    findings = sorted(findings, key=lambda f: (_sev_rank(f.severity), f.path, f.line))
    return {
        "schema": "d0xed-architect/report",
        "version": VERSION,
        "generated": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "root": os.path.abspath(root),
        "duration_s": round(duration, 3),
        "nodes": nodes or {},
        "payments": payments or [],
        "counts": severity_counts(findings),
        "manifest_root": manifest_root(findings),
        "findings": [f.to_dict() for f in findings],
    }


_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _sev_rank(sev: str) -> int:
    return _SEV_ORDER.get(sev, 9)


def severity_counts(findings: list) -> dict:
    out = {k: 0 for k in _SEV_ORDER}
    for f in findings:
        sev = f.severity if isinstance(f, Evidence) else f.get("severity", "info")
        out[sev] = out.get(sev, 0) + 1
    return out


# ── verification ───────────────────────────────────────────────────────────

@dataclass
class VerifyResult:
    ok: int = 0
    stale: list = field(default_factory=list)      # file changed since audit
    unverifiable: list = field(default_factory=list)  # file gone / unreadable
    untouched: list = field(default_factory=list)  # snippet no longer on that line

    @property
    def passed(self) -> bool:
        return not (self.untouched or self.unverifiable)

    def as_dict(self) -> dict:
        return {
            "verified": self.ok,
            "stale_files": self.stale,
            "unverifiable": self.unverifiable,
            "snippet_mismatch": self.untouched,
            "manifest_root": self.manifest_root,
            "passed": self.passed,
        }

    manifest_root: str = ""


def verify_report(report: dict, root: str) -> VerifyResult:
    """Re-hash the tree and confirm every finding still points at its bytes.

    Distinguishes three outcomes, because collapsing them would be dishonest:
      * verified     — file hash matches and the snippet is still on that line
      * stale        — file hash changed (finding was true at the audited revision)
      * unverifiable — file is gone or unreadable
    Sweeping a real finding into "stale" by editing one line is the known
    limitation; the file hash is recorded so the drift is always visible.
    """
    res = VerifyResult()
    res.manifest_root = report.get("manifest_root", "")
    cache: dict[str, tuple[str | None, list]] = {}

    for raw in report.get("findings", []):
        f = Evidence.from_dict(raw)
        if f.path not in cache:
            abspath = os.path.join(root, f.path)
            try:
                cache[f.path] = (sha256_file(abspath), _read_lines(abspath))
            except OSError:
                cache[f.path] = (None, [])
        digest, lines = cache[f.path]

        if digest is None:
            res.unverifiable.append(f.path)
            continue
        if digest != f.file_sha256:
            res.stale.append(f.path)
            continue
        if 1 <= f.line <= len(lines) and lines[f.line - 1].strip()[:MAX_SNIPPET] == f.snippet:
            res.ok += 1
        else:
            res.untouched.append(f"{f.path}:{f.line}")
    return res


def _read_lines(path: str) -> list:
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return fh.read().splitlines()


def to_json(report: dict) -> str:
    return json.dumps(report, indent=2)