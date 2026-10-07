"""Escalation ladder tests.

The two tests that matter:
  1. a normal server-rendered page must NOT escalate (score 0). If it does, we
     have rebuilt the slow thing we were avoiding.
  2. an SPA shell MUST escalate and come back with the JS-injected content.
     If it doesn't, "HTTP-first" is just "broken on SPAs".

The end-to-end pair runs against a local server, so it proves the real ladder
(http -> classify -> render) rather than mocking it.
"""

from __future__ import annotations

import http.server
import os
import socket
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from architect import escalate as esc  # noqa: E402
from architect.http import Response  # noqa: E402

PASS = FAIL = 0

RENDER_AVAILABLE = True
try:
    import playwright  # noqa: F401
    PLAYWRIGHT_OK = True
except Exception:
    PLAYWRIGHT_OK = False


def check(label, cond, detail: object = ""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ✓ {label}")
    else:
        FAIL += 1
        print(f"  ✗ {label}  {detail}")


def resp(html, ctype="text/html; charset=utf-8", status=200):
    return Response(url="http://x/", status=status, headers={},
                    body=html.encode(), content_type=ctype)


# --------------------------------------------------------------- unit: classify

# A believable server-rendered page. Must score 0.
STATIC_PAGE = """<!doctype html><html><head><title>D0xed Dev</title>
<style>.a{color:#0af}</style></head><body>
<header><h1>D0xed Dev</h1><nav><a href="/a">Alpha</a> <a href="/b">Beta</a></nav></header>
<main><h2>Builder cockpit</h2>
<p>Welcome to the D0xed Dev builder cockpit. This page is server rendered and
contains a real paragraph of prose that a crawler should be able to read without
ever starting a browser. We include enough words here to comfortably clear the
thin-text threshold, because a page like this is exactly the case that must not
escalate. Real content, present in the HTML, no JavaScript required at all.</p>
<p>A second paragraph for good measure, describing the token, the scanner lanes,
and the research feed that the operator maintains on a daily cadence.</p>
</main>
<footer><p>(c) 2026 D0xed Dev</p></footer>
<script src="/analytics.js"></script>
</body></html>"""

# A React-style shell: thin text, big script, mount point.
SPA_SHELL = """<!doctype html><html><head><title>App</title></head>
<body><div id="root"></div>
<script>%s</script></body></html>""" % ("var x=%d;" % 0 + "var y=1;" * 300)

NOSCRIPT_PAGE = """<!doctype html><html><head><title>App</title></head><body>
<noscript>You need to enable JavaScript to run this app.</noscript>
<div id="app"></div></body></html>"""


def test_classify():
    v = esc.looks_js_dependent(resp(STATIC_PAGE))
    check("static page does NOT escalate", not v.needs_render, repr(v))
    check("static page scores 0", v.score == 0, f"score={v.score} {v.reasons}")

    v = esc.looks_js_dependent(resp(SPA_SHELL))
    check("SPA shell escalates", v.needs_render, repr(v))
    check("SPA reason mentions thin-text", any("thin-text" in r for r in v.reasons), v.reasons)

    v = esc.looks_js_dependent(resp(NOSCRIPT_PAGE))
    check("noscript 'enable JS' escalates", v.needs_render, repr(v))

    v = esc.looks_js_dependent(resp('{"a":1}', ctype="application/json"))
    check("JSON does not escalate", not v.needs_render, repr(v))
    check("JSON reason is non-html", v.reasons == ["non-html"], v.reasons)

    # An empty body scores 3 (thin-text + near-empty) and deliberately does NOT
    # escalate: a blank response is almost always an empty/broken endpoint, and
    # starting a browser for it is pure waste. Real shells carry a mount marker,
    # which is what pushes them over the threshold.
    v = esc.looks_js_dependent(resp(""))
    check("empty body does NOT escalate (no marker)", not v.needs_render, repr(v))
    check("empty body scores below threshold", v.score == 3, f"score={v.score}")


def test_visible_text():
    t = esc.visible_text(STATIC_PAGE)
    check("text extraction drops tags", "<p>" not in t and "Welcome" in t, t[:60])
    check("text extraction drops scripts", "var y" not in t, t[:60])


def test_budget():
    b = esc.EscalationBudget(max_renders=2)
    check("budget allows 2", b.spend() and b.spend())
    check("budget refuses 3rd", not b.spend())
    check("budget records skip", b.skipped == 1, f"skipped={b.skipped}")
    check("budget exhausted flag", b.exhausted)


# ---------------------------------------------------- end-to-end against a server

SPA_HTML = """<!doctype html><html><head><title>SPA</title></head><body>
<div id="root"></div>
<script>
document.getElementById('root').innerHTML =
  '<h1>Rendered by JavaScript</h1><p>' + ('filler words to clear the threshold ' .repeat(20)) + '</p>';
</script></body></html>"""

PAGES = {"/static.html": STATIC_PAGE, "/spa.html": SPA_HTML}


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        body = PAGES.get(self.path)
        if body is None:
            self.send_response(404); self.end_headers(); return
        b = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def log_message(self, format, *args):  # noqa: A002,D102
        pass


def serve():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
    httpd = http.server.HTTPServer(("127.0.0.1", port), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, port


def test_ladder_e2e():
    httpd, port = serve()
    base = f"http://127.0.0.1:{port}"
    try:
        # 1. static page: must NOT start a browser
        r, v = esc.fetch_smart(base + "/static.html")
        check("static page fetched over HTTP", r.status == 200, f"status={r.status}")
        check("static page NOT rendered", not r.rendered, f"rendered={r.rendered}")
        check("static page has its prose", "builder cockpit" in r.text, r.text[:80])

        # 2. SPA: must escalate, and the content must only exist post-JS
        raw_shell = SPA_HTML
        check("SPA shell has no rendered heading before JS",
              "Rendered by JavaScript" not in esc.visible_text(raw_shell))

        if not PLAYWRIGHT_OK:
            print("  ! playwright missing — skipping render half of the ladder")
            return
        r, v = esc.fetch_smart(base + "/spa.html")
        check("SPA escalated to a browser", r.rendered, f"rendered={r.rendered} {v.reasons}")
        check("SPA content present after render",
              "Rendered by JavaScript" in r.text, r.text[:120])
        check("verdict explains why", bool(v.reasons), v.reasons)

        # 3. budget: exhausted budget must fall back, not crash
        b = esc.EscalationBudget(max_renders=0)
        r, v = esc.fetch_smart(base + "/spa.html", budget=b)
        check("exhausted budget falls back to HTTP", not r.rendered, f"rendered={r.rendered}")
        check("exhausted budget is reported", "budget-exhausted" in v.reasons, v.reasons)

        # 4. allow_render=False must never start a browser
        r, v = esc.fetch_smart(base + "/spa.html", allow_render=False)
        check("allow_render=False never renders", not r.rendered, f"rendered={r.rendered}")
    finally:
        httpd.shutdown()


def main():
    print("escalation ladder:")
    test_classify()
    test_visible_text()
    test_budget()
    test_ladder_e2e()
    print(f"\n{PASS} passed, {FAIL} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
