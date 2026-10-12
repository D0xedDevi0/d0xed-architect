"""Bounded, static-only audit/site-map/doctor reports rendered for Telegram.

Never exceeds `max_len`. Every finding line shows ``path:line`` and a secret-
masked snippet plus its sha256 receipts. Nothing here can leak a secret —
snippets are already masked upstream in `github_audit`/`deep_audit`.
"""
from __future__ import annotations

from .crawl_cmd import SiteMap
from . import persona
from .deep_audit import DeepReport
from .github_audit import AuditOutcome

# ── persona copy (single source of truth for Telegram) ─────────────────────
# Derived from Looper #706's on-chain metadata — see PERSONA.md. Do NOT set
# Telegram copy by hand; change it here and re-apply.

DESCRIPTION = (
    "🟦 DEVin — Looper #706. Builder/Engineer · agent operator. "
    "Walkie-talkie in hand, night shift at the command desk.\n\n"
    "Came up inside mcp router side logs and never fully left. "
    "Reads state, not vibes.\n\n"
    "Send a GitHub repo and I read it cold — secrets, risky patterns, dep rot, "
    "import cycles — every hit stamped path:line with sha256 receipts. "
    "Send a URL and I map it, robots first.\n\n"
    "Static only. I never run your code, never spend, never touch a wallet.\n\n"
    "Wire a tool. Debug a workflow. Ship an integration."
)

ABOUT = ("Looper #706. Reads state, not vibes. Static-only repo + site "
         "auditor — never runs your code.")

# Looper #706's art, sent as the /start welcome (Telegram fetches the URL, so
# the bot itself never makes an outbound request for it).
PHOTO = persona.IMAGE

COMMANDS = [
    {"command": "start", "description": "Show the intro"},
    {"command": "help", "description": "Commands and how to use them"},
    {"command": "lore", "description": "Who DEVin is (on-chain identity)"},
    {"command": "audit", "description": "Read a GitHub repo cold (secrets, risks)"},
    {"command": "debug", "description": "Deep architecture / debug report"},
    {"command": "map", "description": "Map a public site (robots first)"},
    {"command": "crawl", "description": "Crawl a public site: pages, links, assets"},
    {"command": "sitemap", "description": "Read a site's sitemap.xml inventory"},
    {"command": "link", "description": "Shareable links to add DEVin anywhere"},
    {"command": "bundle", "description": "Seal a public repo into one encrypted file"},
    {"command": "doctor", "description": "Self-diagnostics"},
]

# Deep-link payloads: https://t.me/<bot>?start=<payload>. A payload only ever
# selects which sentence the welcome opens with — it never carries a target,
# never authorizes anything, and never reaches a handler as an instruction.
DEEPLINK_PAYLOADS = {
    "audit": "/audit <github-url> — paste a repo and I read it cold.",
    "debug": "/debug <github-url> — deep read: languages, imports, cycles, CI.",
    "map": "/map <url> — I map one page of a public site, robots first.",
    "crawl": "/crawl <url> [depth 1-4] — I walk it: pages, link graph, assets.",
    "sitemap": "/sitemap <url> — I read its sitemap.xml inventory.",
    "bundle": "/bundle <github-url> — I seal the repo into one encrypted file.",
    "lore": "/lore — who I am, straight off the chain.",
    "group": "Add me to a room and address me: /help@<my-username>",
    "help": "/help — everything I can do.",
}

START_TEXT = (
    "🟦 DEVin — Looper #706. Online.\n\n"
    "Builder/Engineer · agent operator. Night shift command desk. "
    "Reads state, not vibes.\n\n"
    "/audit <github-url> — read a repo cold: secrets, risky patterns, receipts.\n"
    "/debug <github-url> — architecture: languages, imports, cycles, SBOM.\n"
    "/map <url> — map one page of a public site, robots first.\n"
    "/crawl <url> [depth] — walk the site: pages, link graph, assets.\n"
    "/sitemap <url> — read its sitemap.xml inventory.\n"
    "/bundle <github-url> — seal a repo into one encrypted file (DM only).\n"
    "/link — shareable links to put me in a DM or a group.\n"
    "/lore — who I am.   /doctor — self-check.   /help — the rest.\n\n"
    "Static only. I don't run your code, I don't spend, I don't touch wallets.\n"
    "Wire a tool. Debug a workflow. Ship an integration."
)

HELP_TEXT = (
    "DEVin — Looper #706. Read-only auditor.\n\n"
    "/start           — banner\n"
    "/help            — this\n"
    "/audit <url>     — /audit https://github.com/<owner>/<repo>\n"
    "                   static scan: secrets + risky patterns\n"
    "/debug <url>     — same target, deep read:\n"
    "                   languages, imports, cycles, manifests, CI, tests\n"
    "/map <url>       — /map https://example.com (public site only)\n"
    "                   robots first; same-origin links only\n"
    "/crawl <url> [n] — bounded crawl, same-origin, robots on every URL\n"
    "                   n = depth 1-4 (default 2). Pages, link graph,\n"
    "                   assets, external hosts, per-page sha256 receipts.\n"
    "/sitemap <url>   — sitemap.xml + sitemapindex inventory (robots hints first)\n"
    "/bundle <url>    — /bundle https://github.com/<owner>/<repo>\n"
    "                   seals the repo into ONE encrypted file:\n"
    "                   .tar.gz.enc (chacha20-poly1305 + scrypt, RFC 8439)\n"
    "                   with a per-file sha256 manifest + the audit inside.\n"
    "                   DM only — code is never posted into a group.\n"
    "                   Refuses if live credentials are found.\n"
    "/link            — deep links to put me in a DM, a group, or a README\n"
    "/lore            — who I am (on-chain identity)\n"
    "/doctor          — self-diagnostics\n\n"
    "In a group, address me: /audit@DEVinlooperbot https://github.com/o/r\n"
    "Source is read, never executed."
)


def render_start(payload: str | None = None) -> str:
    """The welcome. A deep-link payload only picks the opening line."""
    hint = DEEPLINK_PAYLOADS.get((payload or "").strip().lower())
    if hint:
        return _truncate(f"🟦 DEVin — Looper #706. Online.\n\n{hint}\n\n{START_TEXT}",
                         1024)
    return START_TEXT


def render_link(username: str | None) -> str:
    """Shareable links. `username` is the live getMe username; nothing here is
    a credential and nothing here authorizes access — the allowlist still
    decides who is served."""
    u = (username or "DEVinlooperbot").lstrip("@")
    base = f"https://t.me/{u}"
    lines = [
        "🟦 DEVin — put me to work",
        "",
        f"DM:            {base}",
        f"repo audit:    {base}?start=audit",
        f"deep report:   {base}?start=debug",
        f"site map:      {base}?start=map",
        f"site crawl:    {base}?start=crawl",
        f"sitemap:       {base}?start=sitemap",
        f"add to a group: {base}?startgroup=true",
        "",
        f"Already in a room? Address me by name: /audit@{u} <url>",
        "I stay quiet unless I'm mentioned or replied to.",
        "",
        "Static only — read, never executed. Allowlisted chats only.",
    ]
    return "\n".join(lines)


def render_help() -> str:
    return HELP_TEXT


def _truncate(text: str, max_len: int) -> str:
    if len(text) > max_len:
        text = text[: max_len - 20] + "\n…(truncated)"
    return text


def render_lore(max_len: int = 3600) -> str:
    """Who DEVin is — his on-chain identity, stated without fetching anything."""
    lines = [
        f"🟦 DEVin — Looper #{persona.LOOPER_ID} · ERC-8004 agent {persona.AGENT_ID}",
        f"{persona.AGENT_CLASS} · {persona.SECONDARY_CLASS} · {persona.SPECIALIZATION}",
        "",
        f"origin: {persona.ORIGIN}",
        f"mission: {persona.MISSION}",
        "",
        "trait stack:",
    ]
    lines += [f"  {layer}: {trait}" for layer, trait in persona.TRAITS]
    lines += [
        "",
        f"risk {persona.RISK} · autonomy {persona.AUTONOMY}",
        f"codex: {persona.CODEX}",
        f"sheet: {persona.HELIXA}",
        "",
        "first missions: " + " · ".join(persona.FIRST_MISSIONS),
        persona.SIGNATURE,
    ]
    return _truncate("\n".join(lines), max_len)


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
    langs = getattr(out, "languages", None)
    if langs:
        lines.append("languages: " + ", ".join(
            f"{k}{v}" for k, v in sorted(langs.items(), key=lambda t: -t[1])[:12]))
        lines.append(f"loc: {getattr(out, 'loc', 0)}   engine: "
                     f"{getattr(out, 'engine', '-')}")
    sbom = getattr(out, "sbom", None)
    if sbom:
        lines.append(f"sbom: {len(sbom)} components")
    if out.truncated:
        lines.append("(limits reached — results truncated)")
    for n in (getattr(out, "notes", None) or [])[:6]:
        lines.append(f"note: {n}")
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
    if getattr(out, "loc", 0):
        lines.append(f"loc: {out.loc}   suppressions: "
                     f"{getattr(out, 'suppressions', 0)}")
    sbom = getattr(out, "sbom", None)
    if sbom:
        eco: dict = {}
        for e, _n, _v in sbom:
            eco[e] = eco.get(e, 0) + 1
        lines.append("sbom: " + ", ".join(
            f"{k}={v}" for k, v in sorted(eco.items())) +
            "  e.g. " + ", ".join(f"{n}@{v}" for _e, n, v in sbom[:6]))
    lockfiles = getattr(out, "lockfiles", None)
    if lockfiles:
        lines.append(f"lockfiles: {len(lockfiles)}")
    hotspots = getattr(out, "hotspots", None)
    if hotspots:
        lines.append("hotspots (complexity):")
        for path, score, note in hotspots[:6]:
            lines.append(f"  {score:4d} {path}  ({note})")
    iac = getattr(out, "iac", None)
    if iac:
        lines.append(f"iac/devops({len(iac)}): " + ", ".join(iac[:8]))
    lic = getattr(out, "licenses", None)
    if lic:
        lines.append("licenses: " + ", ".join(lic[:5]))
    lines.append(f"TODO: {out.todo_count}   FIXME: {out.fixme_count}")
    lines.append(
        f"findings: crit={sev.get('critical', 0)} high={sev.get('high', 0)} "
        f"med={sev.get('medium', 0)} low={sev.get('low', 0)}")
    if out.manifest_root:
        lines.append(f"manifest: {out.manifest_root}")
    if out.truncated:
        lines.append("(limits reached — results truncated)")
    for n in (getattr(out, "notes", None) or [])[:8]:
        lines.append(f"note: {n}")
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
