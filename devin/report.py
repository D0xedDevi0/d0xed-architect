"""Bounded, static-only audit/site-map/doctor reports rendered for Telegram.

Never exceeds `max_len`. Every finding line shows ``path:line`` and a secret-
masked snippet plus its sha256 receipts. Nothing here can leak a secret —
snippets are already masked upstream in `github_audit`/`deep_audit`.
"""
from __future__ import annotations

from .crawl_cmd import SiteMap
from . import persona
from . import voice
from .deep_audit import DeepReport
from .github_audit import AuditOutcome

# ── persona copy (single source of truth for Telegram) ─────────────────────
# Derived from Looper #706's on-chain metadata — see PERSONA.md. Do NOT set
# Telegram copy by hand; change it here and re-apply.

DESCRIPTION = (
    "🟦 DEVin — Looper #706. Builder/Engineer · agent operator. "
    "Night-shift desk for the builders on Base: a wizard of the wired, "
    "Reads state, not vibes — nostalgic for old iron, allergic to unread "
    "code.\n\n"
    "Send a repo and I read it cold — secrets, risky patterns, dep rot, "
    "import cycles — every hit stamped path:line with a sha256 sigil.\n\n"
    "Static only. I read your code, I never run it, never spend, "
    "never touch a wallet.\n\n"
    "Wire a tool. Debug a workflow. Ship an integration."
)

ABOUT = ("Looper #706. A wizard of the wired: reads state, not vibes. "
         "Static-only repo + site reader.")

# Looper #706's art, sent as the /start welcome (Telegram fetches the URL, so
# the bot itself never makes an outbound request for it).
PHOTO = persona.IMAGE

COMMANDS = [
    {"command": "start", "description": "Show the intro"},
    {"command": "help", "description": "Commands and how to use them"},
    {"command": "spellbook", "description": "The spellbook: how DEVin works"},
    {"command": "lore", "description": "Who DEVin is (on-chain identity)"},
    {"command": "audit", "description": "Read a GitHub repo cold (secrets, risks)"},
    {"command": "debug", "description": "Deep architecture / debug report"},
    {"command": "map", "description": "Map a public site (robots first)"},
    {"command": "crawl", "description": "Crawl a public site: pages, links, assets"},
    {"command": "sitemap", "description": "Read a site's sitemap.xml inventory"},
    {"command": "link", "description": "Shareable links to add DEVin anywhere"},
    {"command": "sigil", "description": "Stamp your words with a sha256"},
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
    "🟦 DEVin — Looper #706. Online. Night shift, desk lamp on.\n\n"
    "Builder/Engineer · agent operator — the desk for builders on Base. "
    "Reads state, not vibes.\n\n"
    "/audit <github-url> — read a repo cold: secrets, risky patterns, receipts.\n"
    "/debug <github-url> — architecture: languages, imports, cycles, SBOM.\n"
    "/map <url> — map one page of a public site, robots first.\n"
    "/crawl <url> [depth] — walk the site: pages, link graph, assets.\n"
    "/sitemap <url> — read its sitemap.xml inventory.\n"
    "/bundle <github-url> — seal a repo into one encrypted file (DM only).\n"
    "No repo link? send me a .zip or .tar.gz of your own code as a document\n"
    "and I'll audit it — and seal it too when a sealing key is set up.\n"
    "/link — shareable links to put me in a DM or a group.\n"
    "/sigil <words> — stamp your words with a sha256.\n"
    "/lore — who I am.   /doctor — self-check.\n"
    "/help — the rest.   /spellbook — how I work.\n\n"
    "Or just talk to me — ask what I do, or name the machine you grew up on.\n\n"
    "Static only. I read your code, I never run it. No spend, no wallet.\n"
    "Wire a tool. Debug a workflow. Ship an integration."
)

HELP_TEXT = (
    "DEVin — Looper #706. The spellbook.\n"
    "Static-only reader: I read source, I never run it.\n\n"
    "/start           — banner\n"
    "/help            — this\n"
    "/spellbook       — the desk's own words on how I work\n"
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
    "SEND ME CODE     — DM me a .zip / .tar.gz as a *document* (not a photo):\n"
    "                   I statically audit the tree whichever language it is,\n"
    "                   and hand it back sealed as one encrypted file when a\n"
    "                   sealing key is provisioned. DM only, 15 MB cap.\n"
    "                   Your own private code never needs a GitHub token.\n"
    "/sigil <words>   — sha256 of your exact words: the same stamp that\n"
    "                   rides on every finding I file\n"
    "/link            — deep links to put me in a DM, a group, or a README\n"
    "/lore            — who I am (on-chain identity)\n"
    "/doctor          — self-diagnostics\n\n"
    "TALK TO ME       — plain text works: ask who I am, what I do, or name\n"
    "                   the old machine you grew up on. In a room that\n"
    "                   means a mention; in a DM just say it.\n\n"
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


# A room that mentions DEVin without a command gets this, at most once a minute
# per chat: enough to be discoverable, not enough to become a chatterbox.
HINT_TEXT = (
    "🟦 DEVin — Looper #706. Mention me WITH a command and I go to work:\n"
    "/audit@%(u)s <github-url> — read a repo cold: secrets, receipts\n"
    "/crawl@%(u)s <url> [depth] — walk a site, robots first\n"
    "/sitemap@%(u)s <url> — sitemap.xml inventory\n"
    "/map@%(u)s <url> — one page, same-origin links only\n"
    "/bundle@%(u)s <url> — seal a repo into one encrypted file (DM only)\n"
    "Or just talk to me — ask what I do, or name the machine you grew up on.\n"
    "Reply to me, or send /help@%(u)s for the full menu.\n"
    "Static only — I read your code, I never run it."
)


def render_hint(username: str | None = None) -> str:
    """The addressed-but-commandless reply, built from the LIVE username."""
    return HINT_TEXT % {"u": (username or "DEVinlooperbot").lstrip("@")}


# Nothing in the spellbook fit the message: a small in-voice nudge that still
# names a real next step, instead of a bare "not a command".
NUDGE_TEXT = (
    "🟦 No spell for that one — yet. Talk to me plainly and I'll answer in the "
    "desk's voice, or put me to work:\n"
    "/audit <github-url> — read a repo cold\n"
    "/debug <github-url> — architecture, imports, cycles, CI\n"
    "/crawl <url> · /sitemap <url> — walk a public site, robots first\n"
    "/sigil <words> — stamp your words with a sha256\n"
    "/help — the whole spellbook."
)


def render_nudge() -> str:
    return NUDGE_TEXT


def render_sigil(text: str) -> str:
    """Stamp a human's words with the same hash every finding carries."""
    _digest, line = voice.sigil(text)
    return line


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
