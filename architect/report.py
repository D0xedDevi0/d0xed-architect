"""Report rendering — D0xed blueprint style (navy/cyan, 🟦 markers)."""
from __future__ import annotations

import datetime as _dt
import json

B = "🟦"


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def crawl_report(target: str, robots, llms, pages: list, trusts: list,
                 graph_stats: dict, paywalls: list, duration: float) -> str:
    L = []
    L.append(f"# {B} D0XED ARCHITECT — SITE INTELLIGENCE")
    L.append(f"\n**Target:** `{target}`  \n**Run:** {_now()}  \n**Duration:** {duration:.1f}s  \n**Crawler class:** search-index (declared)\n")

    L.append(f"\n## {B} Crawl contract")
    L.append(f"- robots.txt: **{'found' if getattr(robots, 'found', False) else 'absent'}** "
             f"({len(robots.disallow)} disallow, {len(robots.allow)} allow)")
    if robots.signals:
        L.append(f"- content-signals: `{robots.signals}`")
    else:
        L.append("- content-signals: none published")
    L.append(f"- llms.txt: **{'found' if llms.found else 'absent'}**"
             + (f" — “{llms.title}”" if llms.title else ""))
    if llms.sections:
        L.append(f"- llms.txt sections: {', '.join(list(llms.sections)[:8])}")
    L.append(f"- sitemaps: {len(robots.sitemaps)}")
    if paywalls:
        L.append(f"- **402 pay-per-crawl gates hit: {len(paywalls)}**")

    L.append(f"\n## {B} Graph")
    L.append(f"- nodes: **{graph_stats['nodes']}** · edges: **{graph_stats['edges']}**")
    for k, v in sorted(graph_stats["node_kinds"].items()):
        L.append(f"  - {k}: {v}")
    for k, v in sorted(graph_stats["edge_kinds"].items()):
        L.append(f"  - {k} edges: {v}")

    L.append(f"\n## {B} Pages ({len(pages)})")
    L.append("| # | URL | words | trust | flags |")
    L.append("|---|---|---|---|---|")
    for i, (p, t) in enumerate(zip(pages, trusts), 1):
        flags = ",".join(sorted({f[0] for f in t.flags})) or "—"
        L.append(f"| {i} | `{_short(p.url)}` | {p.word_count} | {t.score} {t.verdict} | {flags} |")

    L.append(f"\n## {B} Trust layer")
    hostile = [t for t in trusts if t.verdict != "TRUSTED"]
    L.append(f"- pages scanned: {len(trusts)}")
    L.append(f"- clean: {len(trusts) - len(hostile)} · flagged: **{len(hostile)}**")
    for t in hostile[:15]:
        L.append(f"- `{_short(t.url)}` → **{t.verdict}** ({t.score})")
        for kind, detail in t.flags[:4]:
            L.append(f"  - {kind}: `{detail[:90]}`")

    if paywalls:
        L.append(f"\n## {B} Pay-per-crawl / x402")
        for pw in paywalls:
            L.append(f"- `{_short(pw['url'])}` → 402, price=`{pw.get('price')}`")
        L.append("\n_Architect can settle these via the x402 rail (pay-intent header ready)._")

    if llms.found and llms.sections:
        L.append(f"\n## {B} Agent entry points (from llms.txt)")
        for sec, links in list(llms.sections.items())[:6]:
            for name, url, note in links[:6]:
                L.append(f"- [{name}]({url}){(' — ' + note) if note else ''}")

    L.append(f"\n---\n_{B} D0xed Architect v0.1 — identity-declared crawling on x402 rails. NFA._")
    return "\n".join(L)


def audit_report(res, graph_stats: dict, duration: float) -> str:
    L = []
    L.append(f"# {B} D0XED ARCHITECT — CODE AUDIT")
    L.append(f"\n**Root:** `{res.root}`  \n**Run:** {_now()}  \n**Duration:** {duration:.1f}s\n")

    sc = res.severity_counts()
    L.append(f"\n## {B} Verdict")
    gate = "BLOCK" if sc["critical"] else ("REVIEW" if sc["high"] or sc["medium"] else "PASS")
    L.append(f"- gate: **{gate}**")
    L.append(f"- files scanned: **{res.files_scanned}** ({res.bytes_scanned/1024:.0f} KB)")
    L.append(f"- findings: critical **{sc['critical']}** · high **{sc['high']}** "
             f"· medium **{sc['medium']}** · low **{sc['low']}**")

    L.append(f"\n## {B} Language mix")
    for ext, n in sorted(res.languages.items(), key=lambda x: -x[1])[:12]:
        L.append(f"- `{ext}`: {n}")

    L.append(f"\n## {B} Module graph")
    L.append(f"- nodes: {graph_stats['nodes']} · edges: {graph_stats['edges']}")
    for k, v in sorted(graph_stats["edge_kinds"].items()):
        L.append(f"- {k}: {v}")
    if res.entrypoints:
        L.append(f"\n**Entrypoints detected:**")
        for e in res.entrypoints[:15]:
            L.append(f"- `{e}`")

    crit = [f for f in res.findings if f.severity in ("critical", "high")]
    if crit:
        L.append(f"\n## {B} Critical / High")
        L.append("| sev | kind | file:line | detail |")
        L.append("|---|---|---|---|")
        for f in crit[:60]:
            L.append(f"| {f.severity} | {f.kind} | `{f.path}:{f.line}` | {f.detail} |")

    med = [f for f in res.findings if f.severity == "medium"]
    if med:
        L.append(f"\n## {B} Medium ({len(med)})")
        by_kind: dict = {}
        for f in med:
            by_kind.setdefault(f.kind, []).append(f)
        for kind, items in sorted(by_kind.items(), key=lambda x: -len(x[1])):
            L.append(f"- **{kind}** ×{len(items)} — e.g. `{items[0].path}:{items[0].line}`")

    L.append(f"\n---\n_{B} D0xed Architect v0.1 — honest audit, no greenwash._")
    return "\n".join(L)


def _short(u: str, n: int = 64) -> str:
    u = u.replace("https://", "").replace("http://", "")
    return u if len(u) <= n else u[:n - 1] + "…"


def to_json(obj) -> str:
    return json.dumps(obj, indent=2, default=str)
