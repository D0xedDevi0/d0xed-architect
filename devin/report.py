"""Bounded, static-only audit report rendered for a Telegram reply.

Never exceeds `max_len`. Every finding line shows ``path:line`` and a secret-
masked snippet plus its sha256 receipts. Nothing here can leak a secret —
snippets are already masked upstream in `github_audit`.
"""
from __future__ import annotations

from .github_audit import AuditOutcome

START_TEXT = (
    "DEVin offline scaffold.\n"
    "Commands: /start /help /audit\n"
    "/audit <github-url> — bounded static-only inspection of a public repo."
)

HELP_TEXT = (
    "/start  — show this banner\n"
    "/help   — show this help\n"
    "/audit  — /audit https://github.com/<owner>/<repo>\n"
    "Public repos only. Source is inspected statically and never executed."
)


def render_start() -> str:
    return START_TEXT


def render_help() -> str:
    return HELP_TEXT


def render_report(out: AuditOutcome, max_len: int = 3600) -> str:
    sev = out.severity_counts()
    lines = [
        f"DEVin static audit — {out.owner}/{out.repo} @ {out.ref}",
        f"mode: {out.mode.upper()} (source inspected, never executed)",
        f"files: {out.files_scanned}   bytes: {out.bytes_scanned}",
        (f"findings: crit={sev.get('critical', 0)} high={sev.get('high', 0)} "
         f"med={sev.get('medium', 0)} low={sev.get('low', 0)}"),
        f"manifest: {out.manifest_root or '-'}",
    ]
    if out.truncated:
        lines.append("(limits reached — results truncated)")
    if not out.findings:
        lines.append("no findings")
    for f in out.findings:
        lines.append(f"{f.severity:8s} {f.path}:{f.line} [{f.rule}]")
        lines.append(f"    {f.snippet}")
        lines.append(f"    sha256:{f.snippet_sha256[:16]} (file {f.file_sha256[:16]})")
    text = "\n".join(lines)
    if len(text) > max_len:
        text = text[: max_len - 20] + "\n…(truncated)"
    return text
