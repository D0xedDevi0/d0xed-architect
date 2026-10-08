"""Deterministic, read-only source-tree architecture snapshots and drift.

Imports: Python AST; JS/TS only simple literal import/export-from, require(),
and import() forms (best effort, not a JS parser). Other languages have no
import edges. Dependencies are declared names in requirements.txt/package.json;
entrypoints are Python __main__ guards and root-level main.py/__main__.py,
or package.json bin/main/scripts targets that resolve to eligible files.
"""
from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import time
from collections import Counter

from . import auth
from .nodes import SKIP_DIRS, SOURCE_EXT

LIMITS = [
    "Architecture drift is not a vulnerability finding or a security assessment.",
    "Refactor-heavy commits legitimately produce many module_modified items.",
    "Import extraction is best-effort: Python uses AST, JS/TS recognizes simple literal forms only; other languages are unsupported. Absence of import_added is not proof of no new coupling.",
    "A baseline from one revision says nothing about runtime behaviour.",
    "Dependency inventory covers declared names in requirements.txt and package.json only, not resolved versions or transitive dependencies.",
    "Symlinked files and directories are skipped; unreadable files fail capture rather than silently disappearing.",
]
_JS_EXT = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
_JS_IMPORT = re.compile(
    r"(?:^|;)\s*(?:import\s+(?:[^;\n]*?\s+from\s+)?|export\s+[^;\n]*?\s+from\s+)['\"]([^'\"\n]+)['\"]"
    r"|\b(?:require|import)\s*\(\s*['\"]([^'\"\n]+)['\"]\s*\)", re.M)
_REQ_NAME = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[|[<>=!~;@ ]|$)")


def _canonical(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _digest(obj: dict) -> bytes:
    return hashlib.sha256(_canonical(obj)).digest()


def _payload(snapshot: dict) -> dict:
    return {k: v for k, v in snapshot.items() if k not in ("captured_at", "arch_root", "sig")}


def _python_imports(source: str, rel: str) -> set[str]:
    try:
        tree = ast.parse(source, filename=rel)
    except (SyntaxError, ValueError):
        return set()  # invalid Python cannot be reliably parsed
    result = set()
    parts = rel[:-3].split("/")
    package = parts[:-1] if parts[-1] != "__init__" else parts
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            result.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                base = package[:max(0, len(package) - node.level + 1)]
                if node.level > len(package):
                    continue
                target = ".".join(base + ([node.module] if node.module else []))
                if target:
                    result.add(target)
                else:
                    result.update(".".join(base + [a.name]) for a in node.names if a.name != "*")
            elif node.module:
                result.add(node.module)
    return result


def _deps(root: str) -> set[str]:
    names = set()
    for folder, dirs, files in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and not os.path.islink(os.path.join(folder, d)))
        if "requirements.txt" in files and not os.path.islink(os.path.join(folder, "requirements.txt")):
            with open(os.path.join(folder, "requirements.txt"), encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if line.startswith(("#", "-")):
                        continue
                    m = _REQ_NAME.match(line)
                    if m:
                        names.add(m.group(1).lower().replace("_", "-"))
        if "package.json" in files and not os.path.islink(os.path.join(folder, "package.json")):
            with open(os.path.join(folder, "package.json"), encoding="utf-8") as fh:
                try:
                    data = json.load(fh)
                except (ValueError, UnicodeError):
                    continue
            if isinstance(data, dict):
                for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
                    if isinstance(data.get(section), dict):
                        names.update(data[section].keys())
    return names


def _entrypoints(root: str, modules: dict, python_guards: set[str]) -> set[str]:
    found = set(python_guards)
    found.update(p for p in ("main.py", "__main__.py") if p in modules)
    for rel in modules:
        if os.path.basename(rel) != "package.json":
            continue
        try:
            with open(os.path.join(root, rel), encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError, UnicodeError):
            continue
        if not isinstance(data, dict):
            continue
        targets = []
        for field in ("bin", "main"):
            value = data.get(field)
            if isinstance(value, str):
                targets.append(value)
            elif field == "bin" and isinstance(value, dict):
                targets.extend(v for v in value.values() if isinstance(v, str))
        # Script commands are arbitrary shell strings, not reliably source paths.
        parent = os.path.dirname(rel)
        for target in targets:
            path = os.path.normpath(os.path.join(parent, target)).replace(os.sep, "/")
            if path in modules:
                found.add(path)
    return found


def capture(root: str) -> dict:
    """Inventory eligible source/config files; never write to the audited tree."""
    root = os.path.abspath(root)
    if not os.path.isdir(root):
        raise ValueError(f"not a directory: {root}")
    modules: dict[str, str] = {}
    imports: set[tuple[str, str]] = set()
    guards: set[str] = set()
    languages: Counter[str] = Counter()
    total = 0
    for folder, dirs, files in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and not os.path.islink(os.path.join(folder, d)))
        for name in sorted(files):
            ext = os.path.splitext(name)[1].lower()
            if ext not in SOURCE_EXT and name not in ("Dockerfile", "Makefile"):
                continue
            path = os.path.join(folder, name)
            if os.path.islink(path):
                continue
            with open(path, "rb") as fh:
                data = fh.read()
            rel = os.path.relpath(path, root).replace(os.sep, "/")
            modules[rel] = hashlib.sha256(data).hexdigest()
            total += len(data)
            languages[ext or "(none)"] += 1
            if ext == ".py":
                source = data.decode("utf-8", "replace")
                imports.update((rel, target) for target in _python_imports(source, rel))
                try:
                    tree = ast.parse(source, filename=rel)
                except (SyntaxError, ValueError):
                    continue
                for node in tree.body:
                    if (isinstance(node, ast.If) and isinstance(node.test, ast.Compare)
                        and isinstance(node.test.left, ast.Name) and node.test.left.id == "__name__"
                        and len(node.test.ops) == 1 and isinstance(node.test.ops[0], ast.Eq)
                        and len(node.test.comparators) == 1
                        and isinstance(node.test.comparators[0], ast.Constant)
                        and node.test.comparators[0].value == "__main__"):
                        guards.add(rel)
            elif ext in _JS_EXT:
                source = data.decode("utf-8", "replace")
                for match in _JS_IMPORT.finditer(source):
                    # Ignore whole-line comments; inline comments and template syntax remain limitations.
                    line = source[source.rfind("\n", 0, match.start()) + 1:match.start()].strip()
                    if not line.startswith(("//", "*")):
                        imports.add((rel, match.group(1) or match.group(2)))
    payload = {
        "version": 1, "root_name": os.path.basename(root),
        "modules": dict(sorted(modules.items())),
        "imports": [list(edge) for edge in sorted(imports)],
        "entrypoints": sorted(_entrypoints(root, modules, guards)),
        "external_deps": sorted(_deps(root)),
        "stats": {"files": len(modules), "bytes": total,
                  "languages": dict(sorted(languages.items()))},
    }
    return {**payload, "captured_at": int(time.time()), "arch_root": _digest(payload).hex()}


DEFAULT_KEYDIR = ".architect-keys"

_KINDS = (
    ("modules", "module", "notable", "breaking"),
    ("imports", "import", "info", "notable"),
    ("entrypoints", "entrypoint", "notable", "breaking"),
    ("external_deps", "dep", "notable", "notable"),
)


def diff(baseline: dict, current: dict) -> dict:
    """Compare two captures; signed baselines must be verified by the caller first."""
    drift = []
    for field, prefix, added_sev, removed_sev in _KINDS:
        old, new = baseline[field], current[field]
        old_set = set(map(tuple, old)) if field == "imports" else set(old)
        new_set = set(map(tuple, new)) if field == "imports" else set(new)
        for kind, items, sev in (("added", new_set - old_set, added_sev),
                                  ("removed", old_set - new_set, removed_sev)):
            for item in items:
                target = " -> ".join(item) if field == "imports" else item
                drift.append({"kind": f"{prefix}_{kind}", "target": target,
                              "severity": sev, "detail": f"{prefix.capitalize()} {kind}: {target}."})
    for rel in baseline["modules"].keys() & current["modules"].keys():
        if baseline["modules"][rel] != current["modules"][rel]:
            drift.append({"kind": "module_modified", "target": rel,
                          "severity": "info", "detail": f"Module content changed: {rel}."})
    drift.sort(key=lambda item: (item["kind"], item["target"]))
    counts = Counter(item["kind"] for item in drift)
    summary = dict(sorted(counts.items()))
    digest = _digest({"baseline": baseline["arch_root"],
                      "current": current["arch_root"], "drift": drift}).hex()
    return {"version": 1, "clean": not drift, "drift": drift, "summary": summary,
            "drift_root": digest, "limits": list(LIMITS)}


def sign_baseline(capture_dict: dict, keydir: str = ".architect-keys") -> dict:
    ks = auth.KeyStore(keydir).ensure()
    signer = auth.Signer(ks.signing_key())
    digest = _digest(_payload(capture_dict))
    if capture_dict.get("arch_root") != digest.hex():
        raise auth.AuthError("capture arch_root mismatch")
    return {**capture_dict, "sig": {"alg": "ed25519", "kid": signer.kid,
                                    "identity": auth.fingerprint(ks.signing_pub()),
                                    "value": auth.b64u(signer.priv.sign(digest))}}


def verify_baseline(signed: dict, keydir: str = ".architect-keys") -> tuple[bool, str]:
    try:
        if not isinstance(signed, dict) or not isinstance(signed.get("sig"), dict):
            return False, "missing signature"
        sig = signed["sig"]
        if set(sig) != {"alg", "kid", "identity", "value"} or sig["alg"] != "ed25519":
            return False, "invalid signature metadata"
        digest = _digest(_payload(signed))
        if signed.get("arch_root") != digest.hex():
            return False, "arch_root mismatch"
        ks = auth.KeyStore(keydir)  # Do not create replacement keys on verification.
        if sig["identity"] != auth.fingerprint(ks.signing_pub()) or sig["kid"] != auth.Signer(ks.signing_key()).kid:
            return False, "signing identity mismatch"
        ks.signing_pub().verify(auth.b64ud(sig["value"]), digest)
        return True, ""
    except Exception:
        return False, "signature verification failed"


def sign_drift(report: dict, keydir: str = DEFAULT_KEYDIR) -> dict:
    """Sign the entire canonical drift report, not just its summary root."""
    if not isinstance(report, dict) or not report or "sig" in report:
        raise ValueError("expected an unsigned drift report")
    payload = _canonical(report)
    ks = auth.KeyStore(keydir).ensure()
    signer = auth.Signer(ks.signing_key())
    return {**report, "sig": {"alg": "ed25519", "kid": signer.kid,
                              "identity": auth.fingerprint(ks.signing_pub()),
                              "value": auth.b64u(signer.priv.sign(payload))}}


def verify_drift(signed: dict, keydir: str = DEFAULT_KEYDIR) -> tuple[bool, str]:
    """Verify against a trusted public PEM (or the signing key in keydir)."""
    try:
        if not isinstance(signed, dict) or not isinstance(signed.get("sig"), dict):
            return False, "missing signature"
        sig = signed["sig"]
        if (set(sig) != {"alg", "kid", "identity", "value"}
                or sig["alg"] != "ed25519"
                or not isinstance(sig["kid"], str)
                or not isinstance(sig["identity"], str)
                or not isinstance(sig["value"], str)):
            return False, "invalid signature metadata"
        if sig["kid"] != "d0xed-architect":
            return False, "unknown kid"
        # A third party can receive just node-signing.pub (PEM); never generate
        # replacement keys or require access to a private key for verification.
        pubpath = (keydir if os.path.isfile(keydir) else
                   os.path.join(keydir, "node-signing.pub"))
        if os.path.isfile(pubpath):
            with open(pubpath, "rb") as fh:
                pub = auth.serialization.load_pem_public_key(fh.read())
            if not isinstance(pub, auth.Ed25519PublicKey):
                return False, "invalid public key"
        else:
            privpath = os.path.join(keydir, "node-signing.pem")
            with open(privpath, "rb") as fh:
                priv = auth.serialization.load_pem_private_key(fh.read(), password=None)
            if not isinstance(priv, auth.Ed25519PrivateKey):
                return False, "invalid public key"
            pub = priv.public_key()
        if sig["identity"] != auth.fingerprint(pub):
            return False, "signing identity mismatch"
        value = sig["value"]
        if not re.fullmatch(r"[A-Za-z0-9_-]{86}", value):
            return False, "invalid signature encoding"
        signature = auth.b64ud(value)
        if len(signature) != 64 or auth.b64u(signature) != value:
            return False, "invalid signature encoding"
        pub.verify(signature, _canonical({k: v for k, v in signed.items() if k != "sig"}))
        return True, "ok"
    except (OSError, ValueError, TypeError, KeyError) as exc:
        return False, "signature verification failed"
    except Exception:
        return False, "signature verification failed"
