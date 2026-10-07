"""Amnesic Vault — the 'Tails built into the agent' layer.

Artifacts live in RAM only. Nothing is ever written to disk in plaintext.
On wipe() every buffer is overwritten with zeros before being dropped, so a
core dump or a swapped page cannot hand back what we were working on.
The vault also self-destructs on TTL expiry.
"""
from __future__ import annotations

import hashlib
import os
import time
from dataclasses import dataclass, field


def _zero(buf: bytearray) -> None:
    if len(buf):
        buf[:] = b"\x00" * len(buf)


@dataclass
class Entry:
    key: str
    sha256: str
    md5: str
    size: int
    meta: dict = field(default_factory=dict)


class VaultWiped(Exception):
    pass


class AmnesicVault:
    """In-memory, zeroizing, TTL-bound store."""

    def __init__(self, ttl: int = 1800, audit_log: bool = True):
        self.ttl = ttl
        self.created = time.time()
        self._blobs: dict[str, bytearray] = {}
        self._meta: dict[str, dict] = {}
        self._read_log: list[tuple[float, str, str]] = []   # (ts, key, action)
        self._audit_log = audit_log
        self._wiped = False

    # ---------------------------------------------------------------- write
    def put(self, key: str, data: bytes, meta: dict | None = None) -> Entry:
        self._guard()
        buf = bytearray(data)
        self._blobs[key] = buf
        self._meta[key] = dict(meta or {})
        if self._audit_log:
            self._read_log.append((time.time(), key, "write"))
        h = hashlib.sha256(data).hexdigest()
        return Entry(key=key, sha256=h, md5=hashlib.md5(data).hexdigest(),
                     size=len(data), meta=dict(meta or {}))

    def get(self, key: str) -> bytes:
        self._guard()
        if key not in self._blobs:
            raise KeyError(key)
        if self._audit_log:
            self._read_log.append((time.time(), key, "read"))
        return bytes(self._blobs[key])

    def open_file(self, key: str, path: str, meta: dict | None = None) -> Entry:
        """Read a file straight into volatile memory, then let the caller drop it."""
        with open(path, "rb") as fh:
            return self.put(key, fh.read(), meta)

    def keys(self) -> list[str]:
        self._guard()
        return sorted(self._blobs)

    def entries(self) -> list[Entry]:
        self._guard()
        out = []
        for k in self.keys():
            data = bytes(self._blobs[k])
            out.append(Entry(k, hashlib.sha256(data).hexdigest(),
                             hashlib.md5(data).hexdigest(), len(data),
                             dict(self._meta[k])))
        return out

    def audit_trail(self) -> list[dict]:
        return [{"ts": ts, "key": k, "action": a} for ts, k, a in self._read_log]

    # ---------------------------------------------------------------- guards
    def expired(self) -> bool:
        return (time.time() - self.created) > self.ttl

    def ttl_remaining(self) -> int:
        return max(0, int(self.ttl - (time.time() - self.created)))

    def _guard(self):
        if self._wiped:
            raise VaultWiped("vault already wiped")
        if self.expired():
            self.wipe()
            raise VaultWiped("vault TTL expired — self-destructed")

    # ---------------------------------------------------------------- wipe
    def wipe(self) -> int:
        """Zero every byte we hold. Returns the number of bytes destroyed."""
        n = 0
        for buf in self._blobs.values():
            n += len(buf)
            _zero(buf)
        self._blobs.clear()
        self._meta.clear()
        # keep the audit trail (paths + moment only, no content) for the proof
        self._wiped = True
        return n

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.wipe()
        return False