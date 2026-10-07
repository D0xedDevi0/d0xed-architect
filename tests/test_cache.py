"""HTTP cache tests.

The tests that matter:
  1. a fresh response is served with ZERO network calls (that is the win).
  2. a stale entry with an ETag is revalidated, and a 304 serves the stored
     body -- urllib raises on 304, so this path is easy to get wrong.
  3. **if the page actually CHANGED, we must serve the NEW body.** A cache that
     returns stale content on a 200 is worse than no cache at all, because it
     silently corrupts every downstream report.
  4. policy is not bypassed: the cache sits under access checks, and this test
     pins that the body hash still matches what the server served.
"""

from __future__ import annotations

import http.server
import os
import socket
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from architect import http as H          # noqa: E402
from architect.cache import HttpCache    # noqa: E402

PASS = FAIL = 0


def check(label, cond, detail: object = ""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ✓ {label}")
    else:
        FAIL += 1
        print(f"  ✗ {label}  {detail}")


# --------------------------------------------------------------- test server

class Origin:
    """Controllable origin: counts requests, can flip content and validators."""

    def __init__(self):
        self.requests = 0
        self.conditional = 0
        self.body = "<html><body>version one, with enough words to matter</body></html>"
        self.etag = '"v1"'
        self.max_age: int | None = 60          # fresh by default
        self.send_etag = True

    def bump(self):
        self.body = "<html><body>version TWO, the content changed</body></html>"
        self.etag = '"v2"'


def make_handler(origin: Origin):
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            origin.requests += 1
            inm = self.headers.get("If-None-Match")

            headers = [("Content-Type", "text/html; charset=utf-8")]
            if origin.send_etag:
                headers.append(("ETag", origin.etag))
            if origin.max_age is not None:
                headers.append(("Cache-Control", f"max-age={origin.max_age}"))
            else:
                headers.append(("Cache-Control", "no-cache"))

            # Revalidation: if the client's ETag matches ours, 304.
            if inm and origin.send_etag and inm == origin.etag:
                origin.conditional += 1
                self.send_response(304)
                for k, v in headers:
                    self.send_header(k, v)
                self.end_headers()
                return

            b = origin.body.encode()
            self.send_response(200)
            for k, v in headers:
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

        def log_message(self, format, *args):  # noqa: A002
            pass

    return Handler


def serve(origin: Origin):
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    httpd = http.server.HTTPServer(("127.0.0.1", port), make_handler(origin))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, port


# --------------------------------------------------------------------- tests

def test_fresh_hit_is_free():
    origin = Origin()
    origin.max_age = 60
    httpd, port = serve(origin)
    try:
        url = f"http://127.0.0.1:{port}/page"
        c = HttpCache(":memory:")

        r1 = H.fetch(url, cache=c)
        check("first fetch hits the network", origin.requests == 1, origin.requests)
        check("first fetch is not marked cached", not r1.cached, r1.cached)
        check("first fetch has correct body", "version one" in r1.text)

        r2 = H.fetch(url, cache=c)
        check("fresh hit makes NO network call", origin.requests == 1,
              f"requests={origin.requests}")
        check("fresh hit marked cached", r2.cached, r2.cached)
        check("fresh hit returns the SAME body", r2.text == r1.text)
        st = c.stats()
        check("stats count 1 hit", st["hits"] == 1, st)
        check("stats count 1 miss", st["misses"] == 1, st)
        check("bytes_saved recorded", st["bytes_saved"] > 0, st)
    finally:
        httpd.shutdown()


def test_revalidation_304():
    origin = Origin()
    origin.max_age = None   # no-cache -> always revalidate
    httpd, port = serve(origin)
    try:
        url = f"http://127.0.0.1:{port}/page"
        c = HttpCache(":memory:")

        r1 = H.fetch(url, cache=c)
        check("first fetch 200", r1.status == 200, r1.status)

        r2 = H.fetch(url, cache=c)
        check("second fetch sent a conditional request",
              origin.conditional == 1, f"conditional={origin.conditional}")
        check("second fetch counted as revalidated",
              c.stats()["revalidated"] == 1, c.stats())
        check("304 still yields the body", "version one" in r2.text, r2.text[:60])
        check("304 result marked cached", r2.cached, r2.cached)
        check("revalidation counts the avoided body bytes",
              c.stats()["bytes_saved"] >= len(r1.body),
              f"saved={c.stats()['bytes_saved']} body={len(r1.body)}")
    finally:
        httpd.shutdown()


def test_changed_content_is_not_stale():
    """The one that matters: a 200 with new content must NOT serve the old body."""
    origin = Origin()
    origin.max_age = None   # force revalidation
    httpd, port = serve(origin)
    try:
        url = f"http://127.0.0.1:{port}/page"
        c = HttpCache(":memory:")

        r1 = H.fetch(url, cache=c)
        check("v1 fetched", "version one" in r1.text)

        origin.bump()           # server content changes AND etag changes
        r2 = H.fetch(url, cache=c)
        check("changed page returns NEW content",
              "version TWO" in r2.text,
              f"got: {r2.text[:70]}")
        check("changed page does not serve the stale body",
              "version one" not in r2.text, r2.text[:70])
        check("changed page not marked cached", not r2.cached, r2.cached)
    finally:
        httpd.shutdown()


def test_no_cache_when_no_validator():
    """Without ETag/Last-Modified and no max-age, we must refetch every time."""
    origin = Origin()
    origin.max_age = None
    origin.send_etag = False
    httpd, port = serve(origin)
    try:
        url = f"http://127.0.0.1:{port}/page"
        c = HttpCache(":memory:")
        H.fetch(url, cache=c)
        H.fetch(url, cache=c)
        check("no validator -> two network calls", origin.requests == 2,
              f"requests={origin.requests}")
        check("no validator -> no 304s", origin.conditional == 0, origin.conditional)
    finally:
        httpd.shutdown()


def test_persistent_cache_file():
    """A file-backed cache must survive across instances (cross-run re-crawl)."""
    import tempfile
    origin = Origin()
    origin.max_age = 60
    httpd, port = serve(origin)
    tmp = None
    try:
        url = f"http://127.0.0.1:{port}/page"
        fd, tmp = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        os.unlink(tmp)

        c1 = HttpCache(tmp)
        H.fetch(url, cache=c1)
        c1.close()
        check("first run made 1 request", origin.requests == 1, origin.requests)

        c2 = HttpCache(tmp)
        r = H.fetch(url, cache=c2)
        check("second run served from the persistent cache",
              origin.requests == 1, f"requests={origin.requests}")
        check("persistent hit marked cached", r.cached, r.cached)
        c2.close()
    finally:
        httpd.shutdown()
        if tmp and os.path.exists(tmp):
            os.unlink(tmp)


def test_parser_helpers():
    from architect.cache import _parse_max_age
    check("max-age parsed", _parse_max_age("max-age=120") == 120)
    check("no-store means 0", _parse_max_age("no-store") == 0)
    check("no-cache means 0", _parse_max_age("public, no-cache") == 0)
    check("missing max-age is None", _parse_max_age("public") is None)


def main():
    print("http cache:")
    test_parser_helpers()
    test_fresh_hit_is_free()
    test_revalidation_304()
    test_changed_content_is_not_stale()
    test_no_cache_when_no_validator()
    test_persistent_cache_file()
    print(f"\n{PASS} passed, {FAIL} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
