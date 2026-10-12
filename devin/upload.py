"""Telegram document intake — audit (and optionally seal) a code set a user sends.

This is the private-code path that needs NO GitHub token: the user DMs the bot
an archive of their own repository and DEVin statically audits it, then — when a
sealing key is provisioned — hands back ONE encrypted file.

Boundaries, all tested:
  * DM-only intake. A group never causes a code upload, and never receives one.
  * Size is capped before the download (declared size) AND after it (actual
    bytes), so a lying `file_size` cannot stream an unbounded body into memory.
  * Filename allowlist plus a MAGIC-BYTE check, so a renamed binary or a
    JPEG called `repo.zip` is refused as data, not guessed at.
  * The `file_path` Telegram returns is validated against a strict pattern and
    the fetch is host-pinned to api.telegram.org — a hostile file_path cannot
    redirect the download elsewhere.
  * Extraction reuses the same traversal-safe intake as GitHub tarballs: no
    `..`, no absolute paths, no symlinks or hardlinks, caps on files and bytes.
  * NOTHING is executed, built, imported, or installed. Ever.
"""
from __future__ import annotations

import re
import shutil
from dataclasses import dataclass

from .analysis import AnalysisLimits, extract_tarball, extract_zip

# Only formats we can extract WITHOUT guessing. A plain .tar.gz/.tgz or .zip is
# an explicit "please analyze my tree"; anything else gets an honest refusal.
UPLOAD_EXTENSIONS = (".zip", ".tar.gz", ".tgz")
KIND_ZIP = "zip"
KIND_TGZ = "tgz"

# Telegram's own bot-API download ceiling is 20 MB; stay under it and under the
# transport's response cap (checked at call time in `download_cap`).
MAX_UPLOAD_BYTES = 15_000_000

# Telegram hands back e.g. "documents/file_12.zip". Anything else — absolute
# paths, traversal, encoded separators, a different collection — is refused.
_FILE_PATH = re.compile(r"^(?:documents|files)/[A-Za-z0-9_-]{1,64}"
                        r"(?:\.[A-Za-z0-9]{1,8})?$")
_SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._+@()-]{0,180}$")


class UploadDenied(Exception):
    """The upload cannot be accepted. Message is safe to show the user."""


@dataclass(frozen=True)
class Upload:
    file_id: str
    name: str
    size: int
    kind: str

    def label(self) -> str:
        return self.name or f"upload.{self.kind}"


def extension_of(name: str) -> str:
    lower = (name or "").lower()
    for ext in UPLOAD_EXTENSIONS:
        if lower.endswith(ext):
            return ext
    return ""


def parse_document(msg: dict, max_bytes: int = MAX_UPLOAD_BYTES) -> Upload:
    """Pull a document out of a Telegram message, or refuse.

    Refusals are specific enough to act on ("that is 40 MB, the cap is 15 MB")
    without ever echoing file contents.
    """
    doc = (msg or {}).get("document")
    if not isinstance(doc, dict):
        raise UploadDenied("send me an archive as a *document*, not a photo "
                           "or a compressed video")
    file_id = doc.get("file_id")
    if not isinstance(file_id, str) or not file_id:
        raise UploadDenied("that upload had no usable file id")
    name = doc.get("file_name") or ""
    if not isinstance(name, str) or not _SAFE_NAME.match(name or ""):
        raise UploadDenied("that filename has characters I won't touch — "
                           "rename it and resend")
    ext = extension_of(name)
    if not ext:
        raise UploadDenied(f"I only take {' or '.join(UPLOAD_EXTENSIONS)} — "
                           f"{ext or 'that format'} isn't one I can read safely")
    declared = doc.get("file_size")
    if isinstance(declared, int) and declared > max_bytes:
        raise UploadDenied(f"that is {declared // 1_048_576} MB; my cap is "
                           f"{max_bytes // 1_048_576} MB")
    if isinstance(declared, int) and declared <= 0:
        raise UploadDenied("that upload reports zero bytes")
    return Upload(file_id=file_id, name=name,
                  size=int(declared or 0),
                  kind=KIND_ZIP if ext == ".zip" else KIND_TGZ)


def safe_file_path(path: str | None) -> str | None:
    """Validate the `file_path` Telegram returned. None means refuse."""
    if not isinstance(path, str) or len(path) > 96:
        return None
    if not _FILE_PATH.match(path):
        return None
    return path


def sniff(kind: str, data: bytes) -> bool:
    """Magic-byte confirmation. A name is a claim; the bytes are the evidence."""
    if not data:
        return False
    if kind == KIND_ZIP:
        return data[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")
    if kind == KIND_TGZ:
        return data[:2] == b"\x1f\x8b"
    return False


def download_cap(transport_max: int, requested: int = MAX_UPLOAD_BYTES) -> int:
    """Never ask for more than the transport will actually hand back."""
    return max(1, min(requested, int(transport_max)))


def intake(kind: str, data: bytes, limits: AnalysisLimits | None = None
           ) -> tuple[str, bool]:
    """Extract an accepted upload to a temp tree. Returns (root, truncated).

    `strip_root=False` on purpose: an uploaded archive is the user's own
    layout. Stripping the first component would turn `src/app.py` into
    `app.py` — silent data loss.
    """
    limits = limits or AnalysisLimits()
    if kind == KIND_ZIP:
        root, truncated = extract_zip(data, limits, strip_root=False)
    else:
        root, truncated = extract_tarball(data, limits, strip_root=False)
    if root is None:
        raise UploadDenied("that archive didn't open — it may be truncated "
                           "or not really an archive")
    return root, truncated


def cleanup(root: str | None) -> None:
    """Delete an intake tree. Never raises: cleanup must not mask a report."""
    if root:
        try:
            shutil.rmtree(root, ignore_errors=True)
        except Exception:
            pass
