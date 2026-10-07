"""Bench runner: Crawl4AI.

argv: url max_pages depth   ->  prints one JSON line of metrics.

Same BFS policy as tool_architect.py (same origin, same page cap, same depth)
so the two numbers are comparable rather than flattering either side.
"""
import asyncio
import json
import os
import resource
import sys
import time
import urllib.parse


def _host(u: str) -> str:
    """Host with www stripped — same redirect trap as the architect runner."""
    h = urllib.parse.urlsplit(u).netloc.lower()
    return h[4:] if h.startswith("www.") else h


async def run(url, max_pages, depth):
    from crawl4ai import AsyncWebCrawler, BrowserConfig, CrawlerRunConfig, CacheMode

    u0 = urllib.parse.urlsplit(url)
    origin = f"{u0.scheme}://{u0.netloc}"
    same = _host(url)

    t0 = time.time()
    seen: set[str] = set()
    pages = []
    bytes_total = 0
    edges = 0
    skipped = 0
    md_chars = 0

    queue = [url]
    # crawl4ai resolves the browser through Playwright; BrowserConfig has no
    # executable_path, so this uses the Playwright-managed chromium build.
    bc = BrowserConfig(headless=True, verbose=False)
    rc = CrawlerRunConfig(cache_mode=CacheMode.BYPASS)

    async with AsyncWebCrawler(config=bc) as crawler:
        for _ in range(depth + 1):
            frontier = [u for u in queue if u not in seen][: max_pages * 4]
            if not frontier or len(pages) >= max_pages:
                break
            nxt = []
            for u in frontier:
                if u in seen:
                    continue
                seen.add(u)
                if len(pages) >= max_pages:
                    continue
                try:
                    r = await crawler.arun(u, config=rc)
                except Exception:
                    skipped += 1
                    continue
                if not getattr(r, "success", False):
                    skipped += 1
                    continue

                html = getattr(r, "html", "") or ""
                if not isinstance(html, str):
                    html = str(html)
                bytes_total += len(html.encode("utf-8", "ignore"))

                md = getattr(r, "markdown", "") or ""
                if not isinstance(md, str):
                    md = getattr(md, "raw_markdown", "") or str(md)
                md_chars += len(md)

                pages.append(u)
                links = (getattr(r, "links", {}) or {}).get("internal", []) or []
                for lk in links:
                    href = lk.get("href") if isinstance(lk, dict) else None
                    if not href:
                        continue
                    tgt = urllib.parse.urljoin(u, href).split("#")[0]
                    if _host(tgt) == same and tgt not in seen:
                        nxt.append(tgt)
                        edges += 1
            queue = nxt

    wall = time.time() - t0
    return {
        "tool": "crawl4ai",
        "url": url,
        "pages": len(pages),
        "wall_s": round(wall, 2),
        "bytes": bytes_total,
        "edges": edges,
        "graph_nodes": 0,
        "skipped": skipped,
        "markdown_chars": md_chars,
        "robots_found": None,   # crawl4ai does not fetch robots.txt by default
        "llms_found": None,
        "peak_rss_mb": round(
            resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024, 1),
    }


if __name__ == "__main__":
    u = sys.argv[1]
    mp = int(sys.argv[2]) if len(sys.argv) > 2 else 25
    dp = int(sys.argv[3]) if len(sys.argv) > 3 else 2
    print("BENCH_JSON " + json.dumps(asyncio.run(run(u, mp, dp))))