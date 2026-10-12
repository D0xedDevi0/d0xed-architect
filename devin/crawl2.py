"""Bounded multi-page crawler: site map, link graph, asset and sitemap inventory.

Extends the single-page `/map` into a real, bounded crawl:

  * depth-limited BFS, SAME ORIGIN ONLY (never follows off-origin)
  * robots.txt fetched first and enforced on EVERY URL, fail-closed
  * sitemap.xml / sitemapindex discovery, including Sitemap: lines in robots.txt
  * a link graph with in-degree, so the important pages are visible
  * an asset inventory (by kind) and an external-host tally
  * hard budgets: pages, depth, per-page bytes, total bytes, wall-clock deadline
  * per-page provenance receipts (final URL, status, byte count, sha256)

Safety posture, unchanged from `/map`:
  * page content is HOSTILE DATA. It is parsed by `architect.extract.extract`
    and never interpreted as instructions, never executed, never used to build
    a URL outside the allowlisted origin, and never used to authorize anything.
  * only public http(s) is reachable (`safe_fetch._parts` pinning).
  * XML is parsed only after an explicit `<!ENTITY` rejection and a size cap,
    so a billion-laughs / XXE payload in a sitemap is refused, not expanded.

No credentials, no network of its own (all I/O goes through the injected
`fetch`), no execution, no filesystem writes.
"""
from __future__ import annotations

import hashlib
import re
import time
import urllib.parse
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

from architect import safe_fetch
from architect.crawl_access import CrawlAccess
from architect.extract import extract
from architect.http import parse_robots

_SITEMAP_IN_ROBOTS = re.compile(r"(?im)^\s*sitemap\s*:\s*(\S+)")
_LOC = re.compile(r"(?is)<loc>\s*([^<\s]+)\s*</loc>")
_HTMLISH = ("text/html", "application/xhtml", "text/plain")


class CrawlDenied(Exception):
    """Target or fetch refused (unsafe, off-origin, oversized, unavailable)."""


@dataclass(frozen=True)
class CrawlLimits:
    max_pages: int = 12
    max_depth: int = 2
    max_page_bytes: int = 2_000_000
    max_total_bytes: int = 8_000_000
    max_assets: int = 300
    max_external_hosts: int = 40
    max_url_len: int = 2048
    deadline_s: float = 45.0
    fetch_timeout: float = 20.0


@dataclass
class CrawledPage:
    url: str
    status: int
    depth: int
    title: str = ""
    description: str = ""
    bytes: int = 0
    sha256: str = ""
    links_internal: int = 0
    links_external: int = 0
    assets: int = 0
    error: str = ""


@dataclass
class CrawlReport:
    seed: str
    origin: str
    robots: str = "absent"                    # found | absent | unavailable
    sitemaps: list = field(default_factory=list)
    pages: list = field(default_factory=list)          # CrawledPage, fetch order
    edges: list = field(default_factory=list)          # (from_url, to_url)
    assets: list = field(default_factory=list)         # (url, kind)
    external_hosts: dict = field(default_factory=dict)
    skipped: list = field(default_factory=list)        # (url, reason)
    bytes_total: int = 0
    truncated: bool = False
    elapsed_s: float = 0.0

    # ── derived views ────────────────────────────────────────────────────
    def by_depth(self) -> dict:
        out: dict = {}
        for p in self.pages:
            out.setdefault(p.depth, 0)
            out[p.depth] += 1
        return out

    def in_degree(self) -> dict:
        """How many crawled pages link to each URL (importance signal)."""
        deg: dict = {p.url: 0 for p in self.pages}
        for _src, dst in self.edges:
            if dst in deg:
                deg[dst] += 1
        return deg

    def top_pages(self, n: int = 8) -> list:
        """Most-linked pages first, then shallowest, then shortest URL."""
        deg = self.in_degree()
        return sorted(self.pages,
                      key=lambda p: (-deg.get(p.url, 0), p.depth, len(p.url)))[:n]

    def asset_kinds(self) -> dict:
        out: dict = {}
        for _url, kind in self.assets:
            out[kind] = out.get(kind, 0) + 1
        return out

    def errors(self) -> list:
        return [p for p in self.pages if p.status != 200 or p.error]


def norm_url(url: str) -> str:
    """Normalize for dedupe: drop the fragment, fold the default port, lower
    the host, and collapse an empty path to '/'. Query is preserved."""
    u = urllib.parse.urldefrag(url).url
    try:
        p = urllib.parse.urlsplit(u)
    except ValueError:
        return u
    host = (p.hostname or "").lower()
    port = p.port
    if (p.scheme == "https" and port == 443) or (p.scheme == "http" and port == 80):
        port = None
    netloc = host + (f":{port}" if port else "")
    path = p.path or "/"
    return urllib.parse.urlunsplit((p.scheme, netloc, path, p.query, ""))


def _same_origin(origin: str, target: str) -> bool:
    """Same scheme + host + port. A www.<->apex hop is NOT same-origin."""
    try:
        o = urllib.parse.urlsplit(origin)
        t = urllib.parse.urlsplit(target)
    except ValueError:
        return False
    if t.scheme not in ("http", "https") or not t.hostname:
        return False
    o_port = o.port or (443 if o.scheme == "https" else 80)
    t_port = t.port or (443 if t.scheme == "https" else 80)
    return (t.scheme == o.scheme and t.hostname.lower() == o.hostname.lower()
            and t_port == o_port)


_ASSET_KINDS = {
    ".js": "script", ".mjs": "script", ".css": "style",
    ".png": "image", ".jpg": "image", ".jpeg": "image", ".gif": "image",
    ".svg": "image", ".webp": "image", ".avif": "image", ".ico": "image",
    ".woff": "font", ".woff2": "font", ".ttf": "font", ".otf": "font",
    ".pdf": "document", ".zip": "archive", ".tar": "archive", ".gz": "archive",
    ".mp4": "media", ".webm": "media", ".mp3": "media", ".wav": "media",
    ".json": "data", ".xml": "data", ".csv": "data", ".yml": "data",
    ".yaml": "data", ".wasm": "wasm", ".map": "sourcemap",
}


def asset_kind(url: str) -> str:
    path = urllib.parse.urlsplit(url).path.lower()
    for ext, kind in _ASSET_KINDS.items():
        if path.endswith(ext):
            return kind
    return ""


def _safe_text(resp) -> str:
    """Never let a hostile/odd response body crash us.

    A transport may hand back a body that will not decode, or expose `.text` as
    bytes, or raise inside a lazy property. This normalizes all of that to a
    string so the caller can treat content as data without a try/except at
    every use site.
    """
    try:
        t = resp.text
        if isinstance(t, str):
            return t
        if isinstance(t, (bytes, bytearray)):
            return bytes(t).decode("utf-8", "replace")
    except Exception:
        pass
    try:
        b = resp.body or b""
        if isinstance(b, (bytes, bytearray)):
            return bytes(b).decode("utf-8", "replace")
        return str(b)
    except Exception:
        return ""


def _is_htmlish(ct: str) -> bool:
    ct = (ct or "").lower()
    return (not ct) or any(h in ct for h in _HTMLISH)


def sitemap_urls(xml_text: str, limit: int = 200) -> list:
    """Extract <loc> URLs from a sitemap or sitemapindex.

    Refuses entity-bearing XML outright (billion laughs / XXE) rather than
    relying on parser defaults, then falls back to a regex scan if the document
    is not well-formed for ElementTree.
    """
    if not xml_text or "<!ENTITY" in xml_text or "<!DOCTYPE" in xml_text:
        if "<!ENTITY" in xml_text or "<!DOCTYPE" in xml_text:
            return []
    urls: list = []
    try:
        root = ET.fromstring(xml_text.encode("utf-8", "ignore"))
        for el in root.iter():
            tag = el.tag.rsplit("}", 1)[-1]
            if tag == "loc" and (el.text or "").strip():
                urls.append(el.text.strip())
            if len(urls) >= limit:
                break
    except Exception:
        urls = [m.group(1) for m in _LOC.finditer(xml_text)][:limit]
    clean: list = []
    for u in urls:
        if u.startswith(("http://", "https://")) and len(u) <= 2048:
            clean.append(u)
    return clean[:limit]


def discover_sitemaps(origin: str, robots_text: str, fetch, timeout: float) -> list:
    """Sitemap URLs advertised in robots.txt, plus the conventional guesses.

    Only same-origin candidates are returned, and their existence is NOT
    probed here (the caller fetches them, so every request stays countable).
    """
    found: list = []

    def add(u: str) -> None:
        u = u.strip()
        if not u or u in found:
            return
        try:
            cand = urllib.parse.urljoin(origin + "/", u)
        except ValueError:
            return
        if _same_origin(origin, cand) and len(cand) <= 2048:
            found.append(cand)

    for m in _SITEMAP_IN_ROBOTS.finditer(robots_text or ""):
        add(m.group(1))
    for guess in ("/sitemap.xml", "/sitemap_index.xml", "/sitemap-index.xml",
                  "/sitemap/sitemap.xml"):
        add(origin + guess)
    return found


def sitemap_inventory(url: str, fetch, limits: CrawlLimits | None = None) -> tuple:
    """(origin, sitemaps_fetched, page_urls, nested) for a public site.

    Fetches robots.txt for Sitemap: hints, then each candidate sitemap, and
    descends exactly one level into a <sitemapindex>.
    """
    limits = limits or CrawlLimits()
    try:
        p, _port = safe_fetch._parts(url)
    except safe_fetch.UnsafeURL as e:
        raise CrawlDenied("unsafe URL") from e
    origin = f"{p.scheme}://{p.netloc}"

    robots_text = ""
    try:
        r = fetch(origin + "/robots.txt", limits.fetch_timeout)
        if r.status == 200:
            robots_text = _safe_text(r)
    except Exception:
        robots_text = ""

    fetched: list = []
    page_urls: list = []
    nested: list = []
    total = 0
    for cand in discover_sitemaps(origin, robots_text, fetch, limits.fetch_timeout):
        if len(fetched) >= 6 or total > limits.max_total_bytes:
            break
        try:
            r = fetch(cand, limits.fetch_timeout)
        except Exception:
            continue
        if r.status != 200:
            continue
        fetched.append(cand)
        total += len(r.body or b"")
        xml = _safe_text(r)
        locs = sitemap_urls(xml, limit=limits.max_assets)
        is_index = "<sitemapindex" in xml[:2000].lower()
        for u in locs:
            if is_index:
                if _same_origin(origin, u) and u not in nested and len(nested) < 6:
                    nested.append(u)
            elif _same_origin(origin, u) and u not in page_urls:
                page_urls.append(u)
                if len(page_urls) >= limits.max_assets:
                    break
        for u in list(nested):
            if len(fetched) >= 6 or len(page_urls) >= limits.max_assets:
                break
            if u in fetched:
                continue
            try:
                rr = fetch(u, limits.fetch_timeout)
            except Exception:
                continue
            if rr.status != 200:
                continue
            fetched.append(u)
            total += len(rr.body or b"")
            for v in sitemap_urls(_safe_text(rr), limit=limits.max_assets):
                if _same_origin(origin, v) and v not in page_urls:
                    page_urls.append(v)
    return origin, fetched, page_urls, nested


def crawl_site(url: str, fetch, limits: CrawlLimits | None = None,
               clock=time.monotonic) -> CrawlReport:
    """Bounded, robots-respecting, same-origin BFS crawl of a public site."""
    limits = limits or CrawlLimits()
    started = clock()
    try:
        p, _port = safe_fetch._parts(url)
    except safe_fetch.UnsafeURL as e:
        raise CrawlDenied("unsafe URL") from e
    origin = f"{p.scheme}://{p.netloc}"

    # robots.txt first, fail closed exactly like /map.
    robots = None
    robots_note = "absent"
    robots_text = ""
    try:
        r = fetch(origin + "/robots.txt", limits.fetch_timeout)
    except Exception:
        raise CrawlDenied("robots.txt unavailable; refusing") from None
    if r.status == 200:
        try:
            robots_text = _safe_text(r)
            robots = parse_robots(robots_text)
            robots_note = "found"
        except Exception:
            raise CrawlDenied("robots.txt unparseable; refusing") from None
    elif r.status != 404:
        raise CrawlDenied("robots.txt unavailable; refusing")

    ca = CrawlAccess(origin, robots) if robots is not None else None

    def allowed(u: str) -> bool:
        return ca.allows(u) if ca is not None else True

    seed = norm_url(url)
    if not allowed(seed):
        raise CrawlDenied("robots.txt disallows this URL")

    rep = CrawlReport(seed=seed, origin=origin, robots=robots_note,
                      sitemaps=discover_sitemaps(origin, robots_text, fetch,
                                                 limits.fetch_timeout))
    seen = {seed}
    queue: list = [(seed, 0)]
    external: dict = {}
    assets: list = []
    edges: list = []
    budget_hit = ""

    while queue:
        if len(rep.pages) >= limits.max_pages:
            budget_hit = "page budget reached"
            break
        if rep.bytes_total >= limits.max_total_bytes:
            budget_hit = "byte budget reached"
            break
        if clock() - started > limits.deadline_s:
            budget_hit = "time budget reached"
            break

        cur, depth = queue.pop(0)
        if len(cur) > limits.max_url_len:
            rep.skipped.append((cur, "url too long"))
            continue
        if not _same_origin(origin, cur):
            rep.skipped.append((cur, "off-origin"))
            continue
        if not allowed(cur):
            rep.skipped.append((cur, "robots-disallowed"))
            continue

        page = CrawledPage(url=cur, status=0, depth=depth)
        try:
            resp = fetch(cur, limits.fetch_timeout)
        except Exception:
            page.error = "fetch failed"
            rep.pages.append(page)
            continue

        page.status = resp.status
        body = resp.body or b""
        page.bytes = len(body)
        page.sha256 = hashlib.sha256(body).hexdigest()

        if resp.status != 200:
            page.error = f"HTTP {resp.status}"
            rep.pages.append(page)
            continue
        if page.bytes > limits.max_page_bytes:
            page.error = "page too large"
            rep.pages.append(page)
            continue
        if not _is_htmlish(getattr(resp, "content_type", "")):
            page.error = "not html"
            rep.pages.append(page)
            continue

        rep.bytes_total += page.bytes
        try:
            doc = extract(_safe_text(resp), cur)
        except Exception:
            page.error = "unparseable"
            rep.pages.append(page)
            continue

        page.title = (doc.title or "")[:200]
        page.description = (doc.description or "")[:200]

        for href, _text in doc.links:
            if not href:
                continue
            try:
                target = norm_url(urllib.parse.urljoin(cur, href))
            except ValueError:
                continue
            if len(target) > limits.max_url_len:
                continue
            if _same_origin(origin, target):
                page.links_internal += 1
                edges.append((cur, target))
                if target not in seen and depth + 1 <= limits.max_depth:
                    seen.add(target)
                    queue.append((target, depth + 1))
            else:
                page.links_external += 1
                host = urllib.parse.urlsplit(target).hostname or "?"
                if len(external) < limits.max_external_hosts or host in external:
                    external[host] = external.get(host, 0) + 1

        for href, _text in doc.links:
            if not href:
                continue
            try:
                target = norm_url(urllib.parse.urljoin(cur, href))
            except ValueError:
                continue
            kind = asset_kind(target)
            if kind and len(assets) < limits.max_assets:
                entry = (target, kind)
                if entry not in assets:
                    assets.append(entry)
                    page.assets += 1

        rep.pages.append(page)

    rep.edges = edges
    rep.assets = assets
    rep.external_hosts = dict(sorted(external.items(), key=lambda t: (-t[1], t[0])))
    rep.truncated = bool(budget_hit) or len(queue) > 0
    if budget_hit:
        rep.skipped.append(("", budget_hit))
    rep.elapsed_s = round(clock() - started, 2)
    return rep


def render_crawl(rep: CrawlReport, max_len: int = 3600) -> str:
    lines = [f"crawl {rep.origin}"]
    lines.append(f"pages {len(rep.pages)}  depth<=  "
                 f"{max(rep.by_depth()) if rep.by_depth() else 0}"
                 f"  bytes {rep.bytes_total}  {rep.elapsed_s}s")
    lines.append(f"robots: {rep.robots}  sitemaps: {len(rep.sitemaps)}")
    kinds = rep.asset_kinds()
    if kinds:
        lines.append("assets: " + " ".join(f"{k}={v}" for k, v in
                                           sorted(kinds.items(), key=lambda t: -t[1])))
    if rep.external_hosts:
        top = list(rep.external_hosts.items())[:6]
        lines.append("external: " + " ".join(f"{h}({n})" for h, n in top))
    deg = rep.in_degree()
    lines.append("-- top pages --")
    for p in rep.top_pages(8):
        t = p.title or "(no title)"
        lines.append(f"{deg.get(p.url, 0):3d}<- {p.url}")
        lines.append(f"       {t[:70]}")
    bad = rep.errors()
    if bad:
        lines.append("-- not ok --")
        for p in bad[:6]:
            lines.append(f"{p.status or '-'} {p.url} {p.error}")
    if rep.truncated:
        lines.append("(budget reached — partial map)")
    return "\n".join(lines)[:max_len]


def render_sitemap(origin: str, sitemaps: list, urls: list, nested: list,
                   max_len: int = 3600) -> str:
    lines = [f"sitemap {origin}",
             f"sitemaps found {len(sitemaps)}  urls {len(urls)}"
             f"  nested {len(nested)}"]
    for s in sitemaps[:6]:
        lines.append(f"  {s}")
    for u in urls[:25]:
        lines.append(f"  {u}")
    if len(urls) > 25:
        lines.append(f"  ... {len(urls) - 25} more")
    if not urls:
        lines.append("  (no sitemap URLs found)")
    return "\n".join(lines)[:max_len]
