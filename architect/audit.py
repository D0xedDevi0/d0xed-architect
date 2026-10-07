"""Static code audit: secrets, risky patterns, import graph, architecture stats."""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field

from .graph import Graph

CODE_EXT = {".py", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".sol", ".go",
            ".rs", ".java", ".rb", ".php", ".sh", ".yml", ".yaml", ".json",
            ".toml", ".env", ".sql", ".c", ".cpp", ".h", ".cs", ".kt"}
SKIP_DIRS = {".git", "node_modules", ".next", "dist", "build", "__pycache__",
             ".venv", "venv", ".venv-ml", "vendor", "target", ".cache",
             "site-packages", "lib/python3.13"}

SECRET_RULES = [
    ("aws_key", r"\bAKIA[0-9A-Z]{16}\b", 95),
    ("private_key_block", r"-----BEGIN (RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----[\s\S]{0,60}?[A-Za-z0-9+/]{40,}", 99),
    ("openai_key", r"\bsk-[A-Za-z0-9]{32,}\b", 90),
    ("anthropic_key", r"\bsk-ant-[A-Za-z0-9_\-]{24,}", 90),
    ("github_pat", r"\bgh[pousr]_[A-Za-z0-9]{36,}\b", 92),
    ("slack_token", r"\bxox[baprs]-[A-Za-z0-9-]{10,}", 88),
    ("google_api", r"\bAIza[0-9A-Za-z_\-]{35}\b", 88),
    ("stripe_key", r"\b(sk|rk)_(live|test)_[A-Za-z0-9]{20,}", 90),
    ("jwt", r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}", 70),
    ("hex_privkey", r"(?i)(private[_\-]?key|privkey|secret[_\-]?key)\s*[:=]\s*[\"']?0x[0-9a-f]{64}", 96),
    ("hardcoded_pw", r"(?i)(password|passwd|pwd)\s*[:=]\s*[\"'][^\"']{8,}[\"']", 60),
    ("webhook_secret", r"(?i)webhook[_\-]?secret\s*[:=]\s*[\"'][A-Za-z0-9_\-]{16,}", 75),
]

RISK_RULES = [
    ("eval_use", r"\beval\s*\(", 30, "code execution surface"),
    ("exec_use", r"\bexec\s*\(", 30, "code execution surface"),
    ("shell_true", r"shell\s*=\s*True", 35, "command injection risk"),
    ("os_system", r"os\.system\s*\(", 30, "command injection risk"),
    ("innerhtml", r"\.innerHTML\s*=", 25, "DOM XSS risk"),
    ("dangerously_html", r"dangerouslySetInnerHTML", 25, "React XSS risk"),
    ("pickle_load", r"pickle\.loads?\s*\(", 30, "deserialization RCE"),
    ("yaml_load", r"yaml\.load\s*\((?![^)]*Safe)", 25, "unsafe YAML load"),
    ("tx_origin", r"tx\.origin", 30, "Solidity auth bypass"),
    ("delegatecall", r"\bdelegatecall\b", 35, "proxy storage risk"),
    ("selfdestruct", r"\bselfdestruct\b", 30, "contract kill switch"),
    ("unchecked_send", r"\.(call|send)\{?[^;]*\}\?\(\"\"\)", 20, "unchecked low-level call"),
    ("http_url", r"http://(?!localhost|127\.0\.0\.1)", 10, "plaintext transport"),
    ("cors_star", r"Access-Control-Allow-Origin['\"]?\s*[:,]\s*['\"]\*", 20, "wildcard CORS"),
]

IMPORT_PY = re.compile(r"^\s*(?:from\s+([\w.]+)\s+import|import\s+([\w.]+))", re.M)
IMPORT_JS = re.compile(r"""(?:from\s+['"]([^'"]+)['"]|require\(\s*['"]([^'"]+)['"]\s*\))""")


# Canonical, funds-worthless public dev keys: Anvil / Hardhat accounts #0-#3.
# These are published in every tutorial and hold no value on any network, so
# flagging them only teaches people to ignore the scanner. A real key that
# happens to be shaped the same way still fires — see tests/test_v03.py.
_DEV_KEYS = (
    "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
    "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
    "5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",
    "7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6",
)

_EXAMPLE = re.compile(
    r"(EXAMPLE|PLACEHOLDER|your[-_]?(key|token|secret|api)|AKIAIOSFODNN7|"
    r"AKIAI44QH8DHB|deadbeef|xxx{4,}|0{8,}|<[A-Z_]{3,}>)"
    r"|(" + "|".join(_DEV_KEYS) + r")", re.I)


def _range(doc: str, pat: str):
    for m in re.finditer(pat, doc):
        if _EXAMPLE.search(m.group(0)):
            continue
        yield m


@dataclass
class Finding:
    kind: str
    severity: str
    path: str
    line: int
    detail: str


@dataclass
class AuditResult:
    root: str
    files_scanned: int = 0
    bytes_scanned: int = 0
    findings: list = field(default_factory=list)
    languages: dict = field(default_factory=dict)
    modules: int = 0
    entrypoints: list = field(default_factory=list)

    def severity_counts(self) -> dict:
        c = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in self.findings:
            c[f.severity] = c.get(f.severity, 0) + 1
        return c


def _sev(score: int) -> str:
    if score >= 90:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 30:
        return "medium"
    return "low"


def audit_repo(root: str, graph: Graph | None = None, max_files: int = 5000) -> AuditResult:
    res = AuditResult(root=root)
    seen = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".venv")]
        for fn in filenames:
            ext = os.path.splitext(fn)[1].lower()
            if ext not in CODE_EXT:
                continue
            path = os.path.join(dirpath, fn)
            rel = os.path.relpath(path, root)
            try:
                if os.path.getsize(path) > 2_000_000:
                    continue
                with open(path, "r", encoding="utf-8", errors="replace") as fh:
                    src = fh.read()
            except Exception:
                continue
            seen += 1
            if seen > max_files:
                break
            res.files_scanned += 1
            res.bytes_scanned += len(src)
            res.languages[ext] = res.languages.get(ext, 0) + 1

            if graph is not None:
                graph.node("file", rel, label=fn)

            for name, pat, score in SECRET_RULES:
                for m in _range(src, pat):
                    line = src.count("\n", 0, m.start()) + 1
                    res.findings.append(Finding(
                        f"secret:{name}", _sev(score), rel, line,
                        _mask(m.group(0))))
            for name, pat, score, why in RISK_RULES:
                for m in _range(src, pat):
                    line = src.count("\n", 0, m.start()) + 1
                    res.findings.append(Finding(
                        f"risk:{name}", _sev(score), rel, line, why))

            # import graph
            if ext == ".py":
                for a, b in IMPORT_PY.findall(src):
                    mod = (a or b).split(".")[0]
                    if mod and not mod.startswith("_"):
                        if graph is not None:
                            graph.edge(rel, f"py:{mod}", "imports")
            elif ext in {".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"}:
                for a, b in IMPORT_JS.findall(src):
                    mod = a or b
                    if mod.startswith("."):
                        target = os.path.normpath(os.path.join(os.path.dirname(rel), mod))
                        if graph is not None:
                            graph.edge(rel, target, "imports")
                    else:
                        if graph is not None:
                            graph.edge(rel, f"pkg:{mod.split('/')[0]}", "imports")
                if re.search(r"(createServer|app\.listen|export\s+default\s+async\s+function\s+(GET|POST))", src):
                    res.entrypoints.append(rel)
            elif ext == ".sol":
                if re.search(r"contract\s+\w+", src):
                    res.modules += 1
                    if graph is not None:
                        graph.edge(rel, "solidity", "defines")

    res.entrypoints = sorted(set(res.entrypoints))[:25]
    if graph is not None:
        graph.commit()
    return res


def _mask(s: str) -> str:
    s = s.strip()
    if len(s) <= 12:
        return s[:3] + "***"
    return s[:6] + "…" + s[-4:] + f" ({len(s)} chars)"
