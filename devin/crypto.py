"""Sealed bundles: ChaCha20-Poly1305 AEAD + scrypt, pure stdlib.

Why hand-rolled instead of a library: DEVin ships into environments where no
crypto package is guaranteed, and the bot's hard rules forbid shelling out
(`openssl enc` via subprocess is exactly the pattern the guard test exists to
stop). ChaCha20-Poly1305 is small enough to implement correctly and — crucially
— verifiable: `tests/test_devin_crypto.py` checks this file against the official
RFC 8439 test vectors. If those vectors ever fail, every bundle is suspect and
the suite says so loudly.

Honest scope:
  * Confidentiality + integrity for an artifact IN TRANSIT to one holder of the
    passphrase. That is all.
  * It is NOT a key-exchange, NOT a signature (the holder of the passphrase is
    assumed to be the intended recipient), and NOT protection against a weak
    passphrase. Use a long random passphrase.
  * Not forward-secret: one passphrase, one symmetric key, forever.
  * No claim of side-channel resistance beyond Python's big-int arithmetic.

Container format ("DEVinBNDL1"):

    offset  size  field
    0       10    magic b"DEVinBNDL1"
    10      16    scrypt salt
    26      12    AEAD nonce
    38      4     scrypt n  (big-endian)
    42      4     scrypt r
    46      4     scrypt p
    50      ...   ciphertext || 16-byte Poly1305 tag

The header is authenticated: it is passed as associated data, so a bundle whose
parameters were edited fails to open instead of silently decrypting differently.
"""
from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass

MAGIC = b"DEVinBNDL1"
TAG_LEN = 16
KEY_LEN = 32
NONCE_LEN = 12
SALT_LEN = 16
MASK32 = 0xFFFFFFFF

# scrypt cost. ~34 MB and ~60ms on the VPS: heavy enough to be worth something,
# light enough that a 384M-capped systemd unit can still do it.
SCRYPT_N = 1 << 15
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_MAXMEM = 96 * 1024 * 1024
# Ceilings applied to a bundle we are OPENING, so a hostile file cannot ask us
# for gigabytes of scrypt work.
SCRYPT_N_MAX = 1 << 20
SCRYPT_R_MAX = 32
SCRYPT_P_MAX = 16


class CryptoError(Exception):
    """Base class for crypto failure."""


class IntegrityError(CryptoError):
    """The bundle was altered, truncated, or the passphrase is wrong."""


class FormatError(CryptoError):
    """The bytes are not a bundle we can parse."""


class PassphraseError(CryptoError):
    """The passphrase is unusable (empty/too short) or absent."""


# --------------------------------------------------------------------------- #
# ChaCha20 (RFC 8439 section 2.3)
# --------------------------------------------------------------------------- #
def _rotl(v: int, n: int) -> int:
    return ((v << n) | (v >> (32 - n))) & MASK32


def _quarter(s, a, b, c, d) -> None:
    s[a] = (s[a] + s[b]) & MASK32
    s[d] = _rotl(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & MASK32
    s[b] = _rotl(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & MASK32
    s[d] = _rotl(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & MASK32
    s[b] = _rotl(s[b] ^ s[c], 7)


def _state(key: bytes, counter: int, nonce: bytes) -> list:
    const = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]
    kw = [int.from_bytes(key[i:i + 4], "little") for i in range(0, 32, 4)]
    nw = [int.from_bytes(nonce[i:i + 4], "little") for i in range(0, 12, 4)]
    return const + kw + [counter & MASK32] + nw


def chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    """64 keystream bytes. RFC 8439 section 2.3."""
    if len(key) != KEY_LEN or len(nonce) != NONCE_LEN:
        raise FormatError("chacha20 needs a 32-byte key and a 12-byte nonce")
    st = _state(key, counter, nonce)
    work = list(st)
    for _ in range(10):                       # 20 rounds = 10 double rounds
        _quarter(work, 0, 4, 8, 12)
        _quarter(work, 1, 5, 9, 13)
        _quarter(work, 2, 6, 10, 14)
        _quarter(work, 3, 7, 11, 15)
        _quarter(work, 0, 5, 10, 15)
        _quarter(work, 1, 6, 11, 12)
        _quarter(work, 2, 7, 8, 13)
        _quarter(work, 3, 4, 9, 14)
    out = bytearray()
    for i in range(16):
        out += ((work[i] + st[i]) & MASK32).to_bytes(4, "little")
    return bytes(out)


def chacha20_xor(key: bytes, nonce: bytes, data: bytes, counter: int = 1) -> bytes:
    """Stream-cipher `data`. Counter starts at 1 for AEAD (0 makes the poly key)."""
    out = bytearray(len(data))
    for off in range(0, len(data), 64):
        ks = chacha20_block(key, counter + off // 64, nonce)
        chunk = data[off:off + 64]
        for i, byte in enumerate(chunk):
            out[off + i] = byte ^ ks[i]
    return bytes(out)


# --------------------------------------------------------------------------- #
# Poly1305 (RFC 8439 section 2.5)
# --------------------------------------------------------------------------- #
_P = (1 << 130) - 5
_R_CLAMP = 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF


def poly1305_mac(msg: bytes, key: bytes) -> bytes:
    if len(key) != 32:
        raise FormatError("poly1305 needs a 32-byte one-time key")
    r = int.from_bytes(key[:16], "little") & _R_CLAMP
    s = int.from_bytes(key[16:], "little")
    acc = 0
    for off in range(0, len(msg), 16):
        chunk = msg[off:off + 16]
        n = int.from_bytes(chunk + b"\x01", "little")
        acc = ((acc + n) * r) % _P
    return ((acc + s) & ((1 << 128) - 1)).to_bytes(16, "little")


def _pad16(b: bytes) -> bytes:
    rem = len(b) % 16
    return b"" if rem == 0 else b"\x00" * (16 - rem)


def _mac_data(aad: bytes, ct: bytes) -> bytes:
    return (aad + _pad16(aad) + ct + _pad16(ct)
            + len(aad).to_bytes(8, "little") + len(ct).to_bytes(8, "little"))


# --------------------------------------------------------------------------- #
# AEAD_CHACHA20_POLY1305 (RFC 8439 section 2.8)
# --------------------------------------------------------------------------- #
def aead_seal(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    """Return ciphertext || tag."""
    otk = chacha20_block(key, 0, nonce)[:32]
    ct = chacha20_xor(key, nonce, plaintext, counter=1)
    return ct + poly1305_mac(_mac_data(aad, ct), otk)


def aead_open(key: bytes, nonce: bytes, sealed: bytes, aad: bytes = b"") -> bytes:
    if len(sealed) < TAG_LEN:
        raise FormatError("sealed payload is shorter than its tag")
    ct, tag = sealed[:-TAG_LEN], sealed[-TAG_LEN:]
    otk = chacha20_block(key, 0, nonce)[:32]
    if not hmac.compare_digest(poly1305_mac(_mac_data(aad, ct), otk), tag):
        raise IntegrityError("integrity check failed (altered bundle or wrong key)")
    return chacha20_xor(key, nonce, ct, counter=1)


# --------------------------------------------------------------------------- #
# Key derivation
# --------------------------------------------------------------------------- #
def derive_key(passphrase: str, salt: bytes, n: int = SCRYPT_N, r: int = SCRYPT_R,
               p: int = SCRYPT_P) -> bytes:
    if not isinstance(passphrase, str) or len(passphrase) < 8:
        raise PassphraseError("passphrase must be at least 8 characters")
    return hashlib.scrypt(passphrase.encode("utf-8"), salt=salt, n=n, r=r, p=p,
                          dklen=KEY_LEN, maxmem=SCRYPT_MAXMEM)


# --------------------------------------------------------------------------- #
# Bundle container
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Header:
    salt: bytes
    nonce: bytes
    n: int
    r: int
    p: int

    def aad(self) -> bytes:
        return (MAGIC + self.salt + self.nonce + self.n.to_bytes(4, "big")
                + self.r.to_bytes(4, "big") + self.p.to_bytes(4, "big"))


def _check_params(h: Header) -> None:
    if not (1 < h.n <= SCRYPT_N_MAX and h.n & (h.n - 1) == 0):
        raise FormatError(f"refusing n={h.n}: not a power of two within range")
    if not (1 <= h.r <= SCRYPT_R_MAX) or not (1 <= h.p <= SCRYPT_P_MAX):
        raise FormatError("refusing declared scrypt cost")


def seal_bundle(plaintext: bytes, passphrase: str, *,
                n: int = SCRYPT_N, r: int = SCRYPT_R, p: int = SCRYPT_P,
                salt: bytes | None = None, nonce: bytes | None = None) -> bytes:
    """Encrypt `plaintext` under `passphrase`, returning the whole container.

    The salt and nonce are drawn from os.urandom, so the same input encrypts
    differently every time — never fixed, never derived from the content.
    """
    salt = salt if salt is not None else os.urandom(SALT_LEN)
    nonce = nonce if nonce is not None else os.urandom(NONCE_LEN)
    if len(salt) != SALT_LEN or len(nonce) != NONCE_LEN:
        raise FormatError("salt must be 16 bytes and nonce 12 bytes")
    h = Header(salt=salt, nonce=nonce, n=n, r=r, p=p)
    _check_params(h)
    key = derive_key(passphrase, salt, n=n, r=r, p=p)
    return h.aad() + aead_seal(key, nonce, plaintext, aad=h.aad())


def parse_header(blob: bytes) -> Header:
    if len(blob) < 50 + TAG_LEN:
        raise FormatError("too short to be a bundle")
    if blob[:10] != MAGIC:
        raise FormatError("bad magic: not a DEVin bundle")
    salt = blob[10:26]
    nonce = blob[26:38]
    n = int.from_bytes(blob[38:42], "big")
    r = int.from_bytes(blob[42:46], "big")
    p = int.from_bytes(blob[46:50], "big")
    h = Header(salt=salt, nonce=nonce, n=n, r=r, p=p)
    _check_params(h)
    return h


def open_bundle(blob: bytes, passphrase: str) -> bytes:
    h = parse_header(blob)
    key = derive_key(passphrase, h.salt, n=h.n, r=h.r, p=h.p)
    return aead_open(key, h.nonce, blob[50:], aad=h.aad())


def is_bundle(blob: bytes) -> bool:
    return blob[:10] == MAGIC
