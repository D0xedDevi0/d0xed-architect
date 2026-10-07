"""Integrity: per-artifact digests + a manifest root.

SHA-256 is the security primitive. MD5 is carried alongside as a legacy /
corruption-detection tag only — see HONESTY_NOTE. Never rely on MD5 to prove
nothing was tampered with.
"""
from __future__ import annotations

import hashlib
import json

HONESTY_NOTE = (
    "MD5 is included for legacy interop and accidental-corruption detection. "
    "It is NOT collision-resistant and must never be the only check against a "
    "motivated attacker. SHA-256 (and the manifest root) are authoritative."
)


def digest(data: bytes) -> dict:
    return {"sha256": hashlib.sha256(data).hexdigest(),
            "md5": hashlib.md5(data).hexdigest(),
            "size": len(data)}


def build_manifest(entries: list) -> dict:
    """entries: list of vault.Entry. Order-independent manifest root."""
    rows = []
    for e in sorted(entries, key=lambda x: x.key):
        rows.append({"key": e.key, "sha256": e.sha256, "md5": e.md5,
                     "size": e.size, "meta": e.meta})
    root_src = "\n".join(f"{r['key']}:{r['sha256']}:{r['size']}" for r in rows)
    root = hashlib.sha256(root_src.encode()).hexdigest()
    return {"alg": "sha256", "legacy": "md5", "count": len(rows),
            "root": root, "entries": rows, "note": HONESTY_NOTE}


def verify_payload(manifest: dict, payload: dict) -> tuple[bool, list[str]]:
    """Recompute digests for a decrypted payload and compare to the manifest."""
    problems: list[str] = []
    for row in manifest.get("entries", []):
        key = row["key"]
        if key not in payload:
            problems.append(f"missing artifact: {key}")
            continue
        raw = payload[key]
        got = digest(raw.encode("utf-8") if isinstance(raw, str) else raw)
        if got["sha256"] != row["sha256"]:
            problems.append(f"SHA-256 MISMATCH on {key}")
        elif got["md5"] != row["md5"]:
            problems.append(f"legacy MD5 differs on {key} (warning only)")
    root_src = "\n".join(
        f"{r['key']}:{r['sha256']}:{r['size']}"
        for r in sorted(manifest.get("entries", []), key=lambda x: x["key"]))
    if hashlib.sha256(root_src.encode()).hexdigest() != manifest.get("root"):
        problems.append("MANIFEST ROOT MISMATCH — manifest itself was altered")
    return (not problems), problems


def to_json(m: dict) -> str:
    return json.dumps(m, indent=2, sort_keys=True)