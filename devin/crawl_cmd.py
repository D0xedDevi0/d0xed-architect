"""Bounded, robots-respecting map of a PUBLIC http(s) site.

Fetches exactly one seed page (plus its robots.txt and llms.txt) over the
injected `fetch` callable and reports the seed title and its internal
(same-origin, robots-allowed) links. Page content is treated as hostile DATA:
it is only ever parsed by `architect.extract.extract` and never interpreted as
instructions, never executed, and never followed off-origin.

Reuses architect primitives:
  * `safe_fetch._parts`            — SSRF pinning (public http(s) only)
  * `http.parse_robots` / Robots   — robots.txt rules
  * `crawl_access.CrawlAccess`     — per-origin robots gate for links
  * `extract.extract`              — HTML -> structured Page
"""
from __future__ import annotations

import urllib.parse
from dataclasses import dataclass, field

from architect import safe_fetch
from architect.crawl_access import CrawlAccess
from architect.extract import extract
from architect.http import Robots, parse_robots


class MapDenied(Exception):
    """A target or fetch was refused (unsafe, non-http, oversized, etc.)."""


@dataclass(frozen=True)
class MapLimits:
    max_links: int = 50
    max_bytes: int = 2_000_000
    max_url_len: int = 2048


@dataclass
class SiteMap:
    url: str
    title: str = ""
    robots: str = "absent"            # "found" | "absent" | "unavailable"
    llms: str = "absent"              # "found" | "absent"
    internal_links: list = field(default_factory=list)   # [(url, text)]
    links_capped: bool = False
    truncated: bool = False


def _same_origin(origin: str, target: str) -> bool:
    """True only for same scheme + host + port. Stricter than www-aliasing so a
    www.<->apex hop is treated as off-origin and never followed."""
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


def site_map(url: str, fetch, limits: MapLimits | None = None,
             timeout: float = 60.0) -> SiteMap:
    """Map a public site's seed page. `fetch(url, timeout) -> Response` must
    return an object with `.status`, `.body` (bytes), and `.text`."""
    limits = limits or MapLimits()
    try:
        # SSRF pinning: only public http(s), no userinfo/fragment/odd ports.
        p, _port = safe_fetch._parts(url)
    except safe_fetch.UnsafeURL as e:
        raise MapDenied("unsafe URL") from e
    origin = f"{p.scheme}://{p.netloc}"

    # robots.txt FIRST, fail-closed (mirrors architect's strict posture):
    #   200  -> obey it;  404 -> absent (allow all);  anything else
    #   (5xx/403/timeout/unparseable) -> refuse rather than guess.
    robots = Robots()
    robots_note = "absent"
    try:
        r = fetch(origin + "/robots.txt", timeout)
    except Exception:
        raise MapDenied("robots.txt unavailable; refusing") from None
    if r.status == 200:
        try:
            robots = parse_robots(r.text)
            robots_note = "found"
        except Exception:
            raise MapDenied("robots.txt unparseable; refusing") from None
    elif r.status != 404:
        raise MapDenied("robots.txt unavailable; refusing")

    ca = CrawlAccess(origin, robots)
    # The seed itself must be robots-allowed — never fetch a disallowed page.
    if not ca.allows(url):
        raise MapDenied("robots.txt disallows this URL")

    try:
        resp = fetch(url, timeout)
    except Exception:
        raise MapDenied("fetch failed") from None
    if resp.status != 200:
        raise MapDenied(f"seed page unavailable (HTTP {resp.status})")
    if len(resp.body) > limits.max_bytes:
        raise MapDenied("seed page too large")

    page = extract(resp.text, url)

    links: list[tuple[str, str]] = []
    capped = False
    for href, text in page.links:
        if not href:
            continue
        target = urllib.parse.urldefrag(urllib.parse.urljoin(url, href)).url
        if not _same_origin(origin, target):
            continue                 # never follow off-origin links
        if not ca.allows(target):
            continue                 # robots-disallowed link is dropped
        if len(links) >= limits.max_links:
            capped = True
            break
        links.append((target, (text or "")[:80]))

    llms_note = "absent"
    try:
        lr = fetch(origin + "/llms.txt", timeout)
        if lr.status == 200 and "html" not in (lr.content_type or "").lower():
            llms_note = "found"
    except Exception:
        pass

    return SiteMap(url=url, title=page.title, robots=robots_note, llms=llms_note,
                   internal_links=links, links_capped=capped,
                   truncated=capped)
