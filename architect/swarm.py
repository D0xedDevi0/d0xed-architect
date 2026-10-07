"""D0x Swarm — an amnesic audit session: crawl/audit in RAM, seal to one
recipient, hand out a single-use token, then wipe.

    open artifacts -> vault (RAM only)
      -> integrity manifest (sha256 root + md5 legacy)
      -> AES-256-GCM seal
      -> session key wrapped to the recipient's X25519 key
      -> mint a single-use Ed25519 token bound to the manifest root
      -> WIPE the vault
      -> write the sealed bundle + a content-free proof
"""
from __future__ import annotations

import json
import os
import time
import uuid

from . import audit as _audit
from . import auth as _auth
from . import integrity as _integrity
from . import report as _report
from .graph import Graph
from .vault import AmnesicVault


def run_swarm(root: str, out: str, keydir: str = ".architect-keys",
              ttl: int = 1800, token_ttl: int = 900,
              registry_path: str = ".architect-tokens.db",
              recipe: str = "audit") -> dict:
    t0 = time.time()
    ks = _auth.KeyStore(keydir).ensure()
    registry = _auth.TokenRegistry(registry_path)
    vault = AmnesicVault(ttl=ttl)

    # 1. --- do the work INSIDE the vault; nothing hits disk in plaintext
    graph = Graph(":memory:")
    res = _audit.audit_repo(os.path.abspath(root), graph=graph)
    md = _report.audit_report(res, graph.stats(), time.time() - t0)
    entry = vault.put("report.md", md.encode("utf-8"),
                      meta={"kind": "audit-report", "recipe": recipe,
                            "root": os.path.abspath(root)})
    sc = res.severity_counts()
    vault.put("findings.json", json.dumps({
        "files_scanned": res.files_scanned,
        "bytes_scanned": res.bytes_scanned,
        "severity": sc,
        "languages": res.languages,
        "entrypoints": res.entrypoints,
    }, indent=2).encode(), meta={"kind": "findings"})

    # 2. --- integrity manifest
    manifest = _integrity.build_manifest(vault.entries())

    # 3. --- seal to the recipient
    payload = {e.key: vault.get(e.key).decode("utf-8") for e in vault.entries()}
    session_key = os.urandom(32)
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    nonce = os.urandom(12)
    body = json.dumps(payload, separators=(",", ":")).encode()
    ct = AESGCM(session_key).encrypt(nonce, body, b"d0xa-bundle")
    wrapped = _auth.wrap_key(session_key, ks.exchange_pub())

    # 4. --- single-use capability token bound to the manifest root
    signer = _auth.Signer(ks.signing_key())
    token = signer.mint({
        "sub": "swarm:" + uuid.uuid4().hex[:8],
        "aud": "d0xed-architect",
        "scope": "reveal",
        "mrt": manifest["root"],
    }, ttl=token_ttl)
    registry.register(_decode_claims(token))

    bundle = {
        "d0xed_bundle": 1,
        "seal": _auth.b64u(ct),
        "nonce": _auth.b64u(nonce),
        "wrapped_key": wrapped,
        "manifest": manifest,
        "kid": "d0xed-architect-enc",
        "created": int(time.time()),
        "ttl": token_ttl,
    }
    bundle_path = out if out.endswith(".d0xbundle") else out + ".d0xbundle"
    with open(bundle_path, "w", encoding="utf-8") as fh:
        json.dump(bundle, fh, indent=2)

    proof = {
        "bundle": bundle_path,
        "manifest_root": manifest["root"],
        "artifacts": manifest["count"],
        "severity": sc,
        "files_scanned": res.files_scanned,
        "token_scope": "reveal",
        "token_jti_short": _decode_claims(token)["jti"][:12],
        "token_ttl_s": token_ttl,
        "vault_ttl_s": ttl,
        "identity": _auth.fingerprint(ks.signing_pub()),
        "audit_trail": vault.audit_trail(),
    }
    # 5. --- destroy FIRST, so the proof we persist records the wipe
    destroyed = vault.wipe()
    proof["bytes_destroyed"] = destroyed
    proof["vault_wiped"] = True

    proof_path = bundle_path + ".proof.json"
    with open(proof_path, "w", encoding="utf-8") as fh:
        json.dump(proof, fh, indent=2)
    return {"proof": proof, "token": token, "bundle_path": bundle_path,
            "proof_path": proof_path, "signer_pub": ks.signing_pub(),
            "exchange_priv": ks.exchange_key(), "registry": registry,
            "duration": time.time() - t0}


def reveal(bundle_path: str, token: str, keydir: str = ".architect-keys",
           registry_path: str = ".architect-tokens.db") -> dict:
    ks = _auth.KeyStore(keydir).ensure()
    registry = _auth.TokenRegistry(registry_path)
    with open(bundle_path, "r", encoding="utf-8") as fh:
        bundle = json.load(fh)

    # Verify signature / expiry / scope WITHOUT burning the token yet.
    claims = _auth.verify_token(token, ks.signing_pub(), None, scope="reveal")
    if claims.get("mrt") != bundle["manifest"]["root"]:
        raise _auth.AuthError("token is not bound to this manifest root")

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    try:
        session_key = _auth.unwrap_key(bundle["wrapped_key"], ks.exchange_key())
        body = AESGCM(session_key).decrypt(
            _auth.b64ud(bundle["nonce"]), _auth.b64ud(bundle["seal"]),
            b"d0xa-bundle")
        payload = json.loads(body.decode())
    except Exception as e:
        # AES-GCM is authenticated: a flipped ciphertext byte is
        # indistinguishable from a wrong key, and both must be a clean
        # refusal — never an unhandled stack trace.
        raise _auth.AuthError(
            f"sealed bundle failed authentication ({type(e).__name__}) — "
            "tampered in transit or wrong recipient key") from None

    ok, problems = _integrity.verify_payload(bundle["manifest"], payload)
    if ok:
        # Burn the capability ONLY on a clean grant — a crash must not eat the token.
        registry.consume(claims["jti"], claims)
    return {"payload": payload, "integrity_ok": ok, "problems": problems,
            "claims": claims}


def _decode_claims(token: str) -> dict:
    return json.loads(_auth.b64ud(token.split(".")[1]))