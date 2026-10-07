"""Bench runner: D0xed Architect crawler.

argv: url max_pages depth   ->  prints one JSON line of metrics.
Runs in its own process so peak RSS is that tool's, not a shared figure.
"""
import concurrent.futures as cf
import json
import os
import resource
import sys
import time
import urllib.parse

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from architect import extract as _extract   # noqa: E402
from architect import http as _http         # noqa: E402
from architect.graph import Graph           # noqa: E402


def _host(u: str) -> str:
    """Host with www stripped.

    d0xeddev.com 307-redirects to www.d0xeddev.com, so a strict
    `startswith(origin)` test rejects every link and the crawler quietly
    reports a one-page "crawl". Compare hosts, not URL prefixes.
    """
    h = urllib.parse.urlsplit(u).netloc.lower()
    return h[4:] if h.startswith("www.") else h


def run(url, max_pages, depth):
    u0 = urllib.parse.urlsplit(url)
    origin = f"{u0.scheme}://{u0.netloc}"
    same = _host(url)
    robots = _http.load_robots(origin)
    llms = _http.load_llms_txt(origin)

    t0 = time.time()
    seen: set[str] = set()
    pages = []
    bytes_total = 0
    edges = 0
    skipped = 0
    md_chars = 0

    queue = [url]
    for links in (getattr(llms, "sections", {}) or {}).values():
        for _n, u, _note in links:
            if _host(u) == same:
                queue.append(u)

    graph = Graph(":memory:")

    for _ in range(depth + 1):
        frontier = [u for u in queue if u not in seen][: max_pages * 4]
        if not frontier or len(pages) >= max_pages:
            break
        nxt = []
        with cf.ThreadPoolExecutor(max_workers=6) as ex:
            futs = {ex.submit(_http.fetch, u, 15): u for u in frontier}
            for fut in cf.as_completed(futs):
                u = futs[fut]
                if u in seen:
                    continue
                seen.add(u)
                if len(pages) >= max_pages:
                    continue
                try:
                    r = fut.result()
                except Exception:
                    skipped += 1
                    continue
                if r.status != 200:
                    skipped += 1
                    continue
                ct = r.content_type or ""
                if "html" not in ct and "text" not in ct:
                    skipped += 1
                    continue
                body = r.body or b""
                bytes_total += len(body)
                p = _extract.extract(r.text or "", u)
                pages.append(u)
                md_chars += len(_extract.to_markdown(p))
                graph.node("page", u, label=p.title or u)
                for href, _t in p.links:
                    tgt = urllib.parse.urljoin(u, href).split("#")[0]
                    if _host(tgt) == same and tgt not in seen:
                        nxt.append(tgt)
                        graph.edge(u, tgt, "links")
                        edges += 1
        queue = nxt

    wall = time.time() - t0
    st = graph.stats()
    return {
        "tool": "d0xed-architect",
        "url": url,
        "pages": len(pages),
        "wall_s": round(wall, 2),
        "bytes": bytes_total,
        "edges": edges,
        "graph_nodes": st.get("nodes", 0),
        "skipped": skipped,
        "markdown_chars": md_chars,
        "robots_found": bool(robots.found),
        "llms_found": bool(llms.found),
        "peak_rss_mb": round(
            resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024, 1),
    }


if __name__ == "__main__":
    u = sys.argv[1]
    mp = int(sys.argv[2]) if len(sys.argv) > 2 else 25
    dp = int(sys.argv[3]) if len(sys.argv) > 3 else 2
    print("BENCH_JSON " + json.dumps(run(u, mp, dp)))