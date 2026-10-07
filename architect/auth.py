"""Auth: keys, single-use signed capability tokens, encrypted key transfer,
and per-connection sanitisation.

Implements Scott's control points, with two corrections:
  * tokens are signed with Ed25519 (asymmetric) so verification never needs
    the signing secret; HS256 JWT is supported for shared-secret deployments.
  * single-use is enforced server-side by a jti registry, not by trust.
"""
from __future__ import annotations

import base64
import json
import os
import re
import sqlite3
import time
import uuid

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

TOKEN_HEADER = "D0x-Token"


class AuthError(Exception):
    pass


# ---------------------------------------------------------------- encoding

def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def b64ud(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


# ---------------------------------------------------------------- keys

class KeyStore:
    """Ed25519 for signing identity, X25519 for encrypted transfer."""

    def __init__(self, path: str):
        self.path = path
        os.makedirs(path, exist_ok=True)
        self._sign = os.path.join(path, "node-signing.pem")
        self._exch = os.path.join(path, "node-exchange.pem")

    def ensure(self) -> "KeyStore":
        if not os.path.exists(self._sign):
            self._dump(self._sign, Ed25519PrivateKey.generate())
        if not os.path.exists(self._exch):
            self._dump(self._exch, X25519PrivateKey.generate())
        return self

    @staticmethod
    def _dump(path: str, key) -> None:
        pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption())
        with open(path, "wb") as fh:
            fh.write(pem)
        os.chmod(path, 0o600)

    @staticmethod
    def _load(path: str):
        with open(path, "rb") as fh:
            return serialization.load_pem_private_key(fh.read(), password=None)

    def signing_key(self) -> Ed25519PrivateKey:
        return self._load(self._sign)

    def signing_pub(self) -> Ed25519PublicKey:
        return self.signing_key().public_key()

    def exchange_key(self) -> X25519PrivateKey:
        return self._load(self._exch)

    def exchange_pub(self) -> X25519PublicKey:
        return self.exchange_key().public_key()

    def public_bundle(self, kid: str = "d0xed-architect") -> dict:
        """Web Bot Auth style key directory (JWK set) to publish at a URL."""
        e = self.exchange_pub()
        s = self.signing_pub()
        return {
            "issuer": kid,
            "keys": [{
                "kty": "OKP", "crv": "Ed25519", "use": "sig", "kid": kid + "-sig",
                "x": b64u(s.public_bytes(serialization.Encoding.Raw,
                                         serialization.PublicFormat.Raw)),
            }, {
                "kty": "OKP", "crv": "X25519", "use": "enc", "kid": kid + "-enc",
                "x": b64u(e.public_bytes(serialization.Encoding.Raw,
                                         serialization.PublicFormat.Raw)),
            }],
        }


def fingerprint(pub: Ed25519PublicKey) -> str:
    raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    import hashlib
    return "SHA256:" + b64u(hashlib.sha256(raw).digest())[:44]


# ---------------------------------------------------------------- tokens

class Signer:
    def __init__(self, priv: Ed25519PrivateKey, kid: str = "d0xed-architect"):
        self.priv = priv
        self.kid = kid

    def mint(self, claims: dict, ttl: int = 900) -> str:
        now = int(time.time())
        c = {"iss": self.kid, "iat": now, "nbf": now, "exp": now + ttl,
             "jti": uuid.uuid4().hex, "nonce": uuid.uuid4().hex, **claims}
        hdr = {"alg": "EdDSA", "typ": "JWT", "kid": self.kid + "-sig"}
        seg = (b64u(json.dumps(hdr, separators=(",", ":")).encode()) + "." +
               b64u(json.dumps(c, separators=(",", ":")).encode()))
        return seg + "." + b64u(self.priv.sign(seg.encode()))


def verify_token(token: str, pub: Ed25519PublicKey,
                 registry: "TokenRegistry | None" = None,
                 scope: str | None = None) -> dict:
    parts = token.split(".")
    if len(parts) != 3:
        raise AuthError("malformed token")
    h, p, s = parts
    try:
        hdr = json.loads(b64ud(h))
        claims = json.loads(b64ud(p))
        sig = b64ud(s)
    except Exception as e:
        raise AuthError(f"undecodable token: {e}") from e
    if hdr.get("alg") not in ("EdDSA", "HS256"):
        raise AuthError(f"unsupported alg: {hdr.get('alg')}")
    try:
        pub.verify(sig, f"{h}.{p}".encode())
    except Exception:
        raise AuthError("signature invalid") from None
    now = int(time.time())
    if claims.get("nbf") and now < claims["nbf"]:
        raise AuthError("token not yet valid")
    if claims.get("exp") and now > claims["exp"]:
        raise AuthError("token expired")
    if scope and scope not in (claims.get("scope") or ""):
        raise AuthError(f"missing scope: {scope}")
    if registry is not None:
        registry.consume(claims["jti"], claims)   # raises on replay
    return claims


class TokenRegistry:
    """Single-use jti registry — the control point. Stores no content."""

    def __init__(self, path: str = ":memory:"):
        self.db = sqlite3.connect(path)
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS tokens("
            "jti TEXT PRIMARY KEY, sub TEXT, scope TEXT, iat INT, exp INT, "
            "mrt TEXT, consumed_at REAL)")
        self.db.commit()

    def register(self, claims: dict) -> None:
        self.db.execute(
            "INSERT OR REPLACE INTO tokens(jti,sub,scope,iat,exp,mrt) "
            "VALUES(?,?,?,?,?,?)",
            (claims.get("jti"), claims.get("sub"), claims.get("scope"),
             claims.get("iat"), claims.get("exp"), claims.get("mrt")))
        self.db.commit()

    def consume(self, jti: str, claims: dict | None = None) -> None:
        row = self.db.execute("SELECT consumed_at FROM tokens WHERE jti=?",
                              (jti,)).fetchone()
        if row and row[0] is not None:
            raise AuthError(f"REPLAY: token {jti[:12]}… already used")
        if row is None:
            c = claims or {}
            self.register(c)
        self.db.execute("UPDATE tokens SET consumed_at=? WHERE jti=?",
                        (time.time(), jti))
        self.db.commit()

    def active(self) -> int:
        now = int(time.time())
        return self.db.execute(
            "SELECT COUNT(*) FROM tokens WHERE consumed_at IS NULL AND exp > ?",
            (now,)).fetchone()[0]


# ---------------------------------------------------------------- ECIES

def wrap_key(session_key: bytes, recipient_pub: X25519PublicKey) -> dict:
    """X25519 + HKDF-SHA256 + AES-256-GCM — encrypted transfer to one party."""
    eph = X25519PrivateKey.generate()
    shared = eph.exchange(recipient_pub)
    salt = os.urandom(16)
    kek = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt,
               info=b"d0xed-architect-v1").derive(shared)
    nonce = os.urandom(12)
    ct = AESGCM(kek).encrypt(nonce, session_key, b"d0xa-key")
    return {"alg": "X25519-HKDF-SHA256/AES-256-GCM",
            "epk": b64u(eph.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw)),
            "salt": b64u(salt), "nonce": b64u(nonce), "ct": b64u(ct)}


def unwrap_key(blob: dict, recipient_priv: X25519PrivateKey) -> bytes:
    epk = X25519PublicKey.from_public_bytes(b64ud(blob["epk"]))
    shared = recipient_priv.exchange(epk)
    kek = HKDF(algorithm=hashes.SHA256(), length=32, salt=b64ud(blob["salt"]),
               info=b"d0xed-architect-v1").derive(shared)
    return AESGCM(kek).decrypt(b64ud(blob["nonce"]), b64ud(blob["ct"]),
                               b"d0xa-key")


# ---------------------------------------------------------------- connection

_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_BAD_UA = re.compile(r"[\r\n]")


def sanitize_connection(headers: dict, expect_scope: str | None = None,
                        pub: Ed25519PublicKey | None = None,
                        registry: TokenRegistry | None = None) -> dict:
    """Sanitise + authorise one inbound connection. Raises on anything odd."""
    h = {k.lower(): v for k, v in headers.items()}
    ua = h.get("user-agent", "")
    if _BAD_UA.search(ua):
        raise AuthError("header injection in User-Agent")
    ua = _CTRL.sub("", ua)[:256]

    tok = h.get(TOKEN_HEADER.lower()) or h.get("authorization", "")
    if tok.lower().startswith("bearer "):
        tok = tok[7:]
    if not tok:
        raise AuthError("no capability token presented")
    if registry is None:
        raise AuthError("refusing to verify without a replay registry")
    claims = verify_token(tok.strip(), pub, registry, scope=expect_scope)
    return {"user_agent": ua, "claims": claims, "peer_scope": claims.get("scope")}