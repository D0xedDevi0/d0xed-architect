"""Bounded, static-only audit/site-map/doctor reports rendered for Telegram.

Never exceeds `max_len`. Every finding line shows ``path:line`` and a secret-
masked snippet plus its sha256 receipts. Nothing here can leak a secret —
snippets are already masked upstream in `github_audit`/`deep_audit`.
"""
from __future__ import annotations

from .crawl_cmd import SiteMap
from .deep_audit import DeepReport
from .github_audit import AuditOutcome

START_TEXT = (
    "🟦 DEVin — read-only audit brain (Looper #706).\n"
    "Commands: /start /help /audit /debug /map /doctor\n"
    "/audit <github-url> — static-only repo scan (secrets, risky patterns).\n"
    "/debug <github-url> — deep static architecture/debug report.\n"
    "/map <url>            — robots-respecting map of a public site.\n"
    "/doctor               — bounded self-diagnostics.\n"
    "Source is inspected statically and never executed."
)

HELP_TEXT = (
    "/start  — show this banner\n"
    "/help   — show this help\n"
    "/audit  — /audit https://github.com/<owner>/<repo>\n"
    "/debug  — /debug https://github.com/<owner>/<repo> (architecture)\n"
    "/map    — /map https://example.com (public site only)\n"
    "/doctor — self-diagnostics\n"
    "Source is inspected statically and never executed."
)


def render_start() -> str:
    return START_TEXT


def render_help() -> str:
    return HELP_TEXT


def _truncate(text: str, max_len: int) -> str:
    if len(text) > max_len:
        text = text[: max_len - 20] + "\n…(truncated)"
    return text


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
    return _truncate("\n".join(lines), max_len)


def render_deep_report(out: DeepReport, max_len: int = 3600) -> str:
    sev = out.severity_counts()
    lines = [
        f"DEVin deep report — {out.owner}/{out.repo} @ {out.ref}",
        f"mode: {out.mode.upper()} (source inspected, never executed)",
        f"files: {out.files_scanned}   bytes: {out.bytes_scanned}",
    ]
    langs = ", ".join(f"{k}{v}" for k, v in sorted(out.languages.items()))
    lines.append(f"languages: {langs or '-'}")
    lines.append(f"modules: {out.modules}")
    if out.entrypoints:
        lines.append("entrypoints: " + ", ".join(out.entrypoints[:10]))
    if out.top_imports:
        lines.append("top imports: " + ", ".join(
            f"{m}({c})" for m, c in out.top_imports[:10]))
    if out.cycles:
        for cyc in out.cycles[:5]:
            lines.append("cycle: " + " -> ".join(cyc))
    if out.manifests:
        for name, deps in out.manifests.items():
            sample = ", ".join(deps[:8]) if deps else "(present)"
            lines.append(f"manifest {name}: {sample}")
    if out.workflows:
        lines.append("workflows: " + ", ".join(out.workflows[:10]))
    if out.tests:
        lines.append(f"tests({len(out.tests)}): " + ", ".join(out.tests[:10]))
    lines.append(f"TODO: {out.todo_count}   FIXME: {out.fixme_count}")
    lines.append(
        f"findings: crit={sev.get('critical', 0)} high={sev.get('high', 0)} "
        f"med={sev.get('medium', 0)} low={sev.get('low', 0)}")
    if out.manifest_root:
        lines.append(f"manifest: {out.manifest_root}")
    if out.truncated:
        lines.append("(limits reached — results truncated)")
    for f in out.findings:
        lines.append(f"{f.severity:8s} {f.path}:{f.line} [{f.rule}]")
        lines.append(f"    {f.snippet}")
        lines.append(f"    sha256:{f.snippet_sha256[:16]} (file {f.file_sha256[:16]})")
    return _truncate("\n".join(lines), max_len)


def render_site_map(sm: SiteMap, max_len: int = 3600) -> str:
    lines = [
        f"DEVin site map — {sm.url}",
        f"title: {sm.title[:200] or '-'}",
        f"robots.txt: {sm.robots}",
        f"llms.txt: {sm.llms}",
        f"internal links: {len(sm.internal_links)}",
    ]
    if sm.links_capped:
        lines.append("(link cap reached)")
    for target, text in sm.internal_links:
        lines.append(f"  {target}")
        if text:
            lines.append(f"      {text[:80]}")
    return _truncate("\n".join(lines), max_len)
