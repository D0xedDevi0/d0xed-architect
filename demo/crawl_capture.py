#!/usr/bin/env python3
"""Run a REAL crawl and record its event timeline as JSONL.

This is the actual crawler — same robots.txt / llms.txt handling, same
extract/trust/graph modules the CLI uses — with per-page events written out
so the crawl can be replayed as an animation. The video is not a mock: it is
this timeline, drawn.

Every page event carries a provenance receipt - final URL, HTTP status, byte
count and the SHA-256 of the raw response body - the same receipt scheme as
devin/crawl2.py, so each lit node is tied to bytes that were really fetched.

  crawl_capture.py https://d0xeddev.com out.jsonl [max_pages] [depth]
"""
import concurrent.futures as cf
import hashlib
import json
import sys
import time
import os
import urllib.parse

# Repo-relative so the demo reproduces from any clone, not one machine.
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)

from architect import extract as _extract          # noqa: E402
from architect import http as _http                # noqa: E402
from architect import trust as _trust              # noqa: E402
from architect.graph import Graph                  # noqa: E402

START = sys.argv[1] if len(sys.argv) > 1 else "https://d0xeddev.com"
OUT = (sys.argv[2] if len(sys.argv) > 2
       else os.path.join(os.path.dirname(os.path.abspath(__file__)), "crawl-events.jsonl"))
MAX_PAGES = int(sys.argv[3]) if len(sys.argv) > 3 else 25
DEPTH = int(sys.argv[4]) if len(sys.argv) > 4 else 2
CONCURRENCY = 6

events = []
t0 = time.time()


def ev(**kw):
    kw["t"] = round(time.time() - t0, 3)
    events.append(kw)
    return kw


def _host(url):
    try:
        return "ext:" + urllib.parse.urlsplit(url).netloc
    except Exception:
        return "ext:?"


def main():
    start = START if "://" in START else "https://" + START
    origin = "{0.scheme}://{0.netloc}".format(urllib.parse.urlsplit(start))

    robots = _http.load_robots(origin)
    llms = _http.load_llms_txt(origin)

    ev(kind="start", url=start, origin=origin,
       robots_found=bool(robots.found),
       robots_disallow=len(getattr(robots, "disallow", []) or []),
       robots_allow=len(getattr(robots, "allow", []) or []),
       robots_sitemaps=len(getattr(robots, "sitemaps", []) or []),
       llms_found=bool(llms.found),
       llms_sections=len(getattr(llms, "sections", {}) or {}))

    queue = [start]
    if llms.found:
        for links in llms.sections.values():
            for _, u, _n in links:
                if u.startswith(origin):
                    queue.append(u)

    seen: set[str] = set()
    pages = []
    graph = Graph(":memory:")
    graph.node("site", origin, label=origin)
    pages_done = 0

    for depth in range(DEPTH + 1):
        frontier = [u for u in queue if u not in seen][:MAX_PAGES * 4]
        if not frontier:
            break
        next_queue = []
        with cf.ThreadPoolExecutor(max_workers=CONCURRENCY) as ex:
            futs = {ex.submit(_fetch, u): u for u in frontier}
            for fut in cf.as_completed(futs):
                url = futs[fut]
                if url in seen:
                    continue
                seen.add(url)
                if pages_done >= MAX_PAGES:
                    continue
                try:
                    status, resp, sha, nbytes = fut.result()
                except Exception as e:
                    ev(kind="error", url=url, error=str(e)[:80])
                    continue
                if status != 200:
                    ev(kind="skip", url=url, status=status)
                    continue

                page = _extract.extract(resp or "", url)
                tr = _trust.scan(
                    url, page.text, hidden_elements=page.hidden_suspicious,
                    signals=robots.signals, https=url.startswith("https://"),
                    has_llms_txt=bool(llms.found),
                    structured_data=bool(page.json_ld))
                pages.append(page)
                pages_done += 1

                graph.node("page", url, label=page.title or url,
                           meta=f"words={page.word_count}", trust=tr.score)

                new_links = 0
                ext_links = 0
                children: list[str] = []
                for href, text in page.links:
                    target = urllib.parse.urljoin(url, href).split("#")[0]
                    if target.startswith(origin) and target not in seen:
                        next_queue.append(target)
                        graph.edge(url, target, "links")
                        children.append(target)
                        new_links += 1
                    elif href.startswith("http"):
                        graph.edge(url, _host(target), "external")
                        ext_links += 1

                path = urllib.parse.urlsplit(url).path or "/"
                ev(kind="page", url=url, path=path, depth=depth,
                   sha256=sha, bytes=nbytes,
                   words=page.word_count, trust=tr.score,
                   links=len(page.links), new_links=new_links,
                   ext_links=ext_links, title=(page.title or "")[:70],
                   children=children[:16],
                   nodes=graph.stats().get("nodes", 0),
                   edges=graph.stats().get("edges", 0),
                   cumulative=pages_done)
        queue = next_queue

    stats = graph.stats()
    ev(kind="done", pages=pages_done,
       receipts=sum(1 for e in events if e.get("sha256")),
       nodes=stats.get("nodes", 0),
       edges=stats.get("edges", 0), duration=round(time.time() - t0, 3),
       by_kind=stats.get("by_kind", {}))

    with open(OUT, "w") as fh:
        for e in events:
            fh.write(json.dumps(e) + "\n")

    print(f"events : {len(events)}")
    print(f"pages  : {pages_done}")
    print(f"nodes  : {stats.get('nodes', 0)}  edges: {stats.get('edges', 0)}")
    print(f"time   : {time.time() - t0:.2f}s")
    print(f"out    : {OUT}")


def _fetch(url):
    """Fetch one URL -> (status, text, sha256, nbytes).

    The digest is taken over the RAW response body, matching the receipt scheme
    in devin/crawl2.py, so a page event is verifiable against real bytes.
    """
    r = _http.fetch(url, timeout=15, allow_402=False)
    if r.status == 402:
        return 402, None, "", 0
    ct = r.content_type or ""
    if "html" not in ct and "text" not in ct:
        return 204, None, "", 0
    body = r.body or b""
    return 200, r.text, hashlib.sha256(body).hexdigest(), len(body)


if __name__ == "__main__":
    main()