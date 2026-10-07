"""Envelope encryption for audit artifacts.

AES-256-GCM with a scrypt-derived key. The passphrase never touches disk;
the ciphertext is self-describing so a user can decrypt without our tool:

    openssl enc -d -aes-256-gcm  # or any AES-GCM impl with the header params
"""
from __future__ import annotations

import base64
import json
import os
import struct

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAGIC = b"D0XA1"
N, R, P = 2 ** 15, 8, 1


def _derive(passphrase: str, salt: bytes, length: int = 32) -> bytes:
    kdf = Scrypt(salt=salt, length=length, n=N, r=R, p=P)
    return kdf.derive(passphrase.encode("utf-8"))


def encrypt(data: bytes, passphrase: str, aad: bytes = b"") -> bytes:
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = _derive(passphrase, salt)
    ct = AESGCM(key).encrypt(nonce, data, aad)
    header = json.dumps({
        "v": 1, "alg": "AES-256-GCM", "kdf": f"scrypt(n={N},r={R},p={P})",
        "salt": base64.b64encode(salt).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "aad": base64.b64encode(aad).decode(),
    }, separators=(",", ":")).encode()
    return MAGIC + struct.pack(">I", len(header)) + header + ct


def decrypt(blob: bytes, passphrase: str) -> bytes:
    if not blob.startswith(MAGIC):
        raise ValueError("not a D0xed Architect envelope")
    off = len(MAGIC)
    (hlen,) = struct.unpack(">I", blob[off:off + 4])
    off += 4
    header = json.loads(blob[off:off + hlen])
    ct = blob[off + hlen:]
    salt = base64.b64decode(header["salt"])
    nonce = base64.b64decode(header["nonce"])
    aad = base64.b64decode(header.get("aad", ""))
    key = _derive(passphrase, salt)
    return AESGCM(key).decrypt(nonce, ct, aad)


def is_envelope(blob: bytes) -> bool:
    return blob[:len(MAGIC)] == MAGIC
