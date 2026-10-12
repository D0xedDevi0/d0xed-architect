"""Encrypted artifact packaging: seal any code set, in any language, for handoff.

What this is: given a bounded static intake (a directory, a GitHub tarball, or
the tree a previous audit already fetched), produce ONE encrypted file that a
human can carry to another machine, plus a manifest that proves what is inside
and what the analysis found.

What this is NOT, and cannot honestly be:
  * not execution — nothing here runs, builds, or imports the code;
  * not deployment — no artifact is published anywhere; the output is a file
    the caller decides what to do with;
  * not a key exchange — the passphrase is symmetric and shared out of band;
  * not a guarantee of language coverage — the language inventory is honest
    breadth (identification by extension/manifest), not semantic understanding.

Safety properties that ARE claimed, and are tested:
  * the manifest inside the bundle carries a SHA-256 per file, so a sealed
    bundle is tamper-evident once opened;
  * opening refuses paths that escape the destination directory (no `..`, no
    absolute paths, no symlink tricks) — a hostile bundle is data, not a
    filesystem instruction;
  * a bundle that would ship LIVE SECRETS is refused by default, because
    encrypting a leaked credential and mailing it somewhere is still a leak.
    `allow_secrets=True` is an explicit, logged, human decision;
  * the passphrase is never written to disk, never logged, never in the result
    object, and never in the rendered receipt.
"""
from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import shutil
import tarfile
import time
from dataclasses import dataclass, field

from .analysis import (AnalysisLimits, _skip_path, analyze_tree, extract_tarball,
                       safe_member)
from .crypto import IntegrityError, is_bundle, open_bundle, seal_bundle

MANIFEST_NAME = "_devin/MANIFEST.json"
AUDIT_NAME = "_devin/AUDIT.json"
BUNDLE_VERSION = 1
ENGINE = "devin-static-v1"

# Finding rules that mean "there is a live credential in here". Refused by
# default because encryption does not un-leak anything.
# Deliberately broad and fail-closed: a refusal here costs the operator one
# `allow_secrets=True`, while a miss mails a live credential to someone. "key"
# covers api_key/private_key/aws_access_key; "auth" covers basic_auth_url.
BLOCKING_HINTS = (
    "secret", "credential", "private", "key", "token", "password", "passwd",
    "pem", "auth", "bearer", "aws", "jwt", "conn_string", "connection_string",
)


class PackError(Exception):
    """Packaging failed for an operational reason."""


class PackRefused(PackError):
    """Packaging was refused by policy (secrets, size, or bounds)."""


@dataclass(frozen=True)
class PackLimits:
    max_files: int = 800
    max_file_bytes: int = 400_000
    max_total_bytes: int = 12_000_000
    # Telegram sendDocument refuses >50MB. Stay far under it: the outer blob and
    # the inner tar both live in memory during packaging.
    max_bundle_bytes: int = 24_000_000
    max_findings: int = 200
    # Ceiling on what we will even download before it becomes a bundle.
    max_tarball_bytes: int = 16_000_000


@dataclass
class PackResult:
    blob: bytes
    label: str
    created_at: str
    source_sha256: str          # inner tar.gz, pre-encryption
    bundle_sha256: str          # the .enc bytes as shipped
    files: int
    languages: dict
    loc: int
    findings: int
    blocking: list              # (rule, path) pairs that were refused/acknowledged
    warnings: list
    plaintext_bytes: int
    manifest: dict = field(default_factory=dict)

    @property
    def encrypted_bytes(self) -> int:
        return len(self.blob)

    def filename(self, slug: str = "") -> str:
        stamp = self.created_at.replace("-", "").replace(":", "").replace("T", "-")
        base = slug or self.label
        return f"DEVin-{base}-{stamp}.tar.gz.enc"


# --------------------------------------------------------------------------- #
# intake
# --------------------------------------------------------------------------- #
def _iter_source_files(root: str, limits: PackLimits) -> tuple[list, list]:
    """Bounded, symlink-free walk. Returns ([(rel, abspath, size)], warnings)."""
    found: list = []
    warnings: list = []
    total = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(
            d for d in dirnames
            if d not in {".git", "node_modules", "__pycache__", ".venv", "venv"}
            and not os.path.islink(os.path.join(dirpath, d)))
        for name in sorted(filenames):
            abspath = os.path.join(dirpath, name)
            rel = os.path.relpath(abspath, root).replace(os.sep, "/")
            if _skip_path(rel) or os.path.islink(abspath):
                continue
            try:
                size = os.path.getsize(abspath)
            except OSError:
                warnings.append(f"unreadable: {rel}")
                continue
            if size > limits.max_file_bytes:
                warnings.append(f"skipped (over {limits.max_file_bytes}B): {rel}")
                continue
            if len(found) >= limits.max_files:
                warnings.append(f"file cap reached ({limits.max_files})")
                break
            if total + size > limits.max_total_bytes:
                warnings.append(f"total byte cap reached ({limits.max_total_bytes})")
                break
            total += size
            found.append((rel, abspath, size))
        if len(found) >= limits.max_files:
            break
    return found, warnings


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _gzip_bytes(raw: bytes) -> bytes:
    """Deterministic gzip: mtime pinned to 0 so the digest is reproducible."""
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", compresslevel=9, mtime=0) as gz:
        gz.write(raw)
    return buf.getvalue()


def _inner_tar(files: list, manifest: dict, audit: dict) -> bytes:
    """Build the tar. Every member is normalized (mtime 0, uid/gid 0, mode 644)
    so the same input always produces the same digest."""
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.GNU_FORMAT) as tf:
        for rel, abspath, size in files:
            try:
                ti = tf.gettarinfo(abspath, arcname=rel)
                ti.mtime = 0
                ti.uid = ti.gid = 0
                ti.uname = ti.gname = ""
                ti.mode = 0o644
                ti.type = tarfile.REGTYPE
                with open(abspath, "rb") as fh:
                    tf.addfile(ti, fh)
            except OSError as e:
                raise PackError(f"cannot read {rel}: {type(e).__name__}") from None
        for name, obj in ((MANIFEST_NAME, manifest), (AUDIT_NAME, audit)):
            payload = json.dumps(obj, indent=2, sort_keys=True).encode("utf-8")
            ti = tarfile.TarInfo(name)
            ti.size = len(payload)
            ti.mtime = 0
            ti.mode = 0o644
            ti.uid = ti.gid = 0
            ti.uname = ti.gname = ""
            tf.addfile(ti, io.BytesIO(payload))
    return _gzip_bytes(raw.getvalue())


def pack_github(url: str, fetch, passphrase: str, *, label: str = "",
                limits: PackLimits | None = None, allow_secrets: bool = False,
                timeout: float = 60.0, token: str | None = None) -> PackResult:
    """Fetch a PUBLIC GitHub repo tarball and seal it.

    `fetch` is the caller's GitHub transport; it is allowlisted to
    api.github.com / codeload.github.com, so this cannot be pointed at an
    arbitrary host.

    With `token`, a PRIVATE repo can be sealed too — the token travels only as
    an Authorization header to the two allowlisted hosts and never enters the
    bundle, the manifest, or an error string. Without a token a private repo is
    a clean refusal, never a partial bundle.

    Mapped into a PackError so a caller that only knows about packaging still
    gets an honest refusal rather than an unhandled audit exception.
    """
    from .github_audit import fetch_public_tarball
    L = limits or PackLimits()
    # Same resolution + branch validation as /audit; raises AuditDenied.
    body, ref_name = fetch_public_tarball(url, fetch, timeout, token,
                                         max_bytes=L.max_tarball_bytes)
    return pack_tarball(body, passphrase,
                        label=label or ref_name.replace("/", "-"),
                        limits=L, allow_secrets=allow_secrets)


def _language_of(rel: str) -> str:
    """Best-effort label from the analyzer's own language map — the manifest
    must never disagree with the audit about what a file is."""
    from .polyglot import LANG_BY_EXT
    return LANG_BY_EXT.get(os.path.splitext(rel)[1].lower(), "")


def _blocking_findings(findings) -> list:
    out = []
    for f in findings:
        sev = (getattr(f, "severity", "") or "").lower()
        rule = (getattr(f, "rule", "") or "").lower()
        if sev in ("high", "critical") and any(k in rule for k in BLOCKING_HINTS):
            out.append((getattr(f, "rule", "?"), getattr(f, "path", "?")))
    return out


def _finding_rows(findings, cap: int) -> list:
    rows = []
    for f in findings[:cap]:
        rows.append({
            "rule": getattr(f, "rule", "?"),
            "severity": getattr(f, "severity", "?"),
            "path": getattr(f, "rel", None) or getattr(f, "path", "?"),
            "line": getattr(f, "line", 0),
            "snippet": getattr(f, "snippet", ""),   # already masked upstream
        })
    return rows


# --------------------------------------------------------------------------- #
# pack
# --------------------------------------------------------------------------- #
def build_pack(root: str, passphrase: str, *, label: str = "code",
               limits: PackLimits | None = None, allow_secrets: bool = False,
               created_at: str | None = None,
               analysis_limits: AnalysisLimits | None = None) -> PackResult:
    """Analyze `root`, seal it, and return the bundle plus its receipts."""
    if not os.path.isdir(root):
        raise PackError("not a directory")
    L = limits or PackLimits()
    created = created_at or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    alim = analysis_limits or AnalysisLimits(
        max_files=L.max_files, max_file_bytes=L.max_file_bytes,
        max_total_bytes=L.max_total_bytes, max_findings=L.max_findings)
    report = analyze_tree(root, alim)

    findings = list(getattr(report, "findings", []) or [])
    blocking = _blocking_findings(findings)
    if blocking and not allow_secrets:
        raise PackRefused(
            "refusing to seal: live credentials detected "
            f"({len(blocking)} high/critical secret finding(s)); "
            "encryption does not un-leak a secret. Rotate first, or re-run "
            "with allow_secrets=True to accept the risk explicitly.")

    files, warnings = _iter_source_files(root, L)
    if not files:
        raise PackRefused("nothing to seal: no readable files within the limits")

    entries = []
    for rel, abspath, size in files:
        entries.append({"path": rel, "bytes": size, "sha256": _sha256_file(abspath),
                        "language": _language_of(rel)})

    langs = dict(getattr(report, "languages", {}) or {})
    loc = int(getattr(report, "loc", 0) or 0)
    manifest = {
        "devin_bundle": BUNDLE_VERSION,
        "engine": ENGINE,
        "label": label,
        "created_at": created,
        "files": entries,
        "file_count": len(entries),
        "languages": langs,
        "loc": loc,
        "findings_count": len(findings),
        "secrets_acknowledged": bool(allow_secrets and blocking),
        "limits": {"max_files": L.max_files, "max_file_bytes": L.max_file_bytes,
                   "max_total_bytes": L.max_total_bytes},
    }
    audit = {
        "findings": _finding_rows(findings, L.max_findings),
        "notes": list(getattr(report, "notes", []) or []),
        "truncated": bool(getattr(report, "truncated", False)),
        "acknowledged_secret_findings": [{"rule": r, "path": p} for r, p in blocking],
    }

    inner = _inner_tar(files, manifest, audit)
    if len(inner) > L.max_bundle_bytes:
        raise PackRefused(
            f"refusing to seal: {len(inner)} bytes exceeds the "
            f"{L.max_bundle_bytes} byte bundle cap")
    blob = seal_bundle(inner, passphrase)

    return PackResult(
        blob=blob, label=label, created_at=created,
        source_sha256=_sha256_bytes(inner), bundle_sha256=_sha256_bytes(blob),
        files=len(entries), languages=langs, loc=loc, findings=len(findings),
        blocking=blocking, warnings=warnings, plaintext_bytes=len(inner),
        manifest=manifest)


def pack_tarball(data: bytes, passphrase: str, **kw) -> PackResult:
    """Seal a GitHub-style tarball, or the tree a previous audit extracted.

    `extract_tarball` owns the temp dir it creates, so we clean it up here.
    """
    if not data:
        raise PackError("no tarball bytes")
    root, _trunc = extract_tarball(data, AnalysisLimits())
    if not root or not os.path.isdir(root):
        raise PackError("could not extract the tarball")
    try:
        return build_pack(root, passphrase, **kw)
    finally:
        shutil.rmtree(root, ignore_errors=True)


# --------------------------------------------------------------------------- #
# open / verify
# --------------------------------------------------------------------------- #
def _safe_member(member_name: str) -> str | None:
    """Bundle member guard.

    Delegates to `analysis.safe_member`, which validates WITHOUT stripping the
    first path component: `analysis._safe_rel` strips a wrapper dir (correct for
    GitHub codeload tarballs) and applying that here would turn `src/app.py`
    into `app.py` and `_devin/MANIFEST.json` into `MANIFEST.json` — silent data
    loss and path collisions. Kept as a named alias so the intent stays visible
    at the call sites.
    """
    return safe_member(member_name)


def _safe_members(tf: tarfile.TarFile) -> list:
    """Reject anything that is not a plain file with a safe relative path."""
    out = []
    for m in tf.getmembers():
        rel = _safe_member(m.name)
        if rel is None or _skip_path(rel):
            raise PackError(f"refusing unsafe member: {m.name!r}")
        if not m.isreg():
            raise PackError(f"refusing non-regular member: {m.name!r}")
        out.append((rel, m))
    return out


def open_pack(blob: bytes, passphrase: str, dest: str,
              limits: PackLimits | None = None) -> dict:
    """Decrypt, verify every file hash, and extract into `dest`.

    Returns the manifest. Raises IntegrityError if the bundle or any member
    fails its digest, PackError if it contains a member we refuse to write.
    """
    L = limits or PackLimits()
    if not is_bundle(blob):
        raise PackError("not a DEVin bundle")
    inner = open_bundle(blob, passphrase)          # IntegrityError on tamper
    os.makedirs(dest, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(inner), mode="r") as tf:
        members = _safe_members(tf)
        names = {rel for rel, _m in members}
        if MANIFEST_NAME not in names:
            raise PackError("bundle has no manifest")
        manifest = json.loads(tf.extractfile(MANIFEST_NAME).read().decode("utf-8"))
        declared = {e["path"]: e for e in manifest.get("files", [])}
        total = 0
        for rel, m in members:
            if rel in (MANIFEST_NAME, AUDIT_NAME):
                continue
            if m.size > L.max_file_bytes:
                raise PackError(f"member over the size cap: {rel}")
            total += m.size
            if total > L.max_total_bytes:
                raise PackError("bundle exceeds the total byte cap")
            if rel not in declared:
                raise PackError(f"member not in the manifest: {rel}")
            payload = tf.extractfile(m).read()
            if _sha256_bytes(payload) != declared[rel]["sha256"]:
                raise IntegrityError(f"digest mismatch for {rel}")
            target = os.path.join(dest, rel)
            os.makedirs(os.path.dirname(target) or dest, exist_ok=True)
            with open(target, "wb") as fh:
                fh.write(payload)
    return manifest


def verify_pack(blob: bytes, passphrase: str) -> dict:
    """Open without writing anything: prove the bundle is intact and list it."""
    inner = open_bundle(blob, passphrase)
    with tarfile.open(fileobj=io.BytesIO(inner), mode="r") as tf:
        members = _safe_members(tf)
        names = {rel for rel, _m in members}
        manifest = (json.loads(tf.extractfile(MANIFEST_NAME).read().decode("utf-8"))
                    if MANIFEST_NAME in names else {})
        declared = {e["path"]: e for e in manifest.get("files", [])}
        checked = 0
        for rel, m in members:
            if rel in (MANIFEST_NAME, AUDIT_NAME):
                continue
            payload = tf.extractfile(m).read()
            if _sha256_bytes(payload) != declared.get(rel, {}).get("sha256"):
                raise IntegrityError(f"digest mismatch for {rel}")
            checked += 1
        return {"manifest": manifest, "checked": checked,
                "members": sorted(names), "source_sha256": _sha256_bytes(inner),
                "bundle_sha256": _sha256_bytes(blob)}


# --------------------------------------------------------------------------- #
# receipt
# --------------------------------------------------------------------------- #
def render_pack(res: PackResult, max_len: int = 3600) -> str:
    """The Telegram receipt. Carries hashes, never the passphrase."""
    langs = ", ".join(f"{k} {v}" for k, v in sorted(res.languages.items())[:6])
    lines = [
        "sealed. 🟦",
        f"label: {res.label}",
        f"files: {res.files} · loc: {res.loc}",
        f"languages: {langs or 'n/a'}",
        f"findings: {res.findings}",
        f"plaintext: {res.plaintext_bytes} B -> sealed: {res.encrypted_bytes} B",
        f"source sha256: {res.source_sha256[:16]}…",
        f"bundle sha256: {res.bundle_sha256[:16]}…",
        "cipher: chacha20-poly1305 + scrypt (RFC 8439)",
        "held: manifest + audit inside the bundle. rotated nothing.",
    ]
    if res.blocking:
        lines.append(f"acknowledged secret findings: {len(res.blocking)}")
    if res.warnings:
        lines.append(f"warnings: {len(res.warnings)} (capped intake)")
    lines.append("passphrase is not stored anywhere. lose it, lose the bundle.")
    return "\n".join(lines)[:max_len]
