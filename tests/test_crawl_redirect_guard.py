"""Real transport must not follow forbidden HTTP/browser navigation."""
import http.server as http_server
import os
import threading
import unittest
from urllib.parse import urlsplit

from architect import escalate, http, x402


class Handler(http_server.BaseHTTPRequestHandler):
    hits = []

    def do_GET(self):
        self.hits.append(self.path)
        if self.path in ("/public", "/encoded"):
            self.send_response(302)
            self.send_header("Location", ("/%2e%2e/private" if
                                     self.path == "/encoded" else "/private"))
            self.end_headers()
        elif self.path == "/shell":
            body = b'<html><body><script>fetch("/private")</script><a href="/private">private</a></body></html>'
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/navigate":
            body = b'<html><body><script>location.href="/private"</script></body></html>'
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/popup":
            body = b'<html><body><script>window.open("/private")</script></body></html>'
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"SECRET" if self.path == "/private" else b"public")

    def log_message(self, *_):
        pass


class RedirectGuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http_server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)

    def setUp(self):
        Handler.hits = []
        self.robots = http.parse_robots("User-agent: *\nDisallow: /private\n")

    def guard(self, url):
        if not self.robots.can_fetch(urlsplit(url).path or "/"):
            raise http.FetchError("robots denied")

    def test_http_redirect_never_requests_denied_target(self):
        with self.assertRaises(http.FetchError):
            http.fetch(self.base + "/public", redirect_guard=self.guard)
        self.assertEqual(Handler.hits, ["/public"])

    def test_encoded_redirect_never_requests_normalized_private(self):
        from architect.crawl_access import CrawlAccess
        policy = CrawlAccess(self.base, self.robots)
        with self.assertRaises(http.FetchError):
            http.fetch(self.base + "/encoded", redirect_guard=policy.require)
        self.assertEqual(Handler.hits, ["/encoded"])

    def test_paid_transport_redirect_never_requests_denied_target(self):
        with self.assertRaises(http.FetchError):
            x402._request("GET", self.base + "/public", {}, 2,
                          redirect_guard=self.guard)
        self.assertEqual(Handler.hits, ["/public"])

    def test_paid_client_passes_guard_into_transport(self):
        from unittest.mock import patch
        policy = x402.PayPolicy(enabled=False)
        with patch.object(x402, "_request", return_value=(200, {}, b"ok")) as request:
            x402.fetch_paid(self.base + "/public", policy,
                            redirect_guard=self.guard)
        guard = request.call_args.kwargs["redirect_guard"]
        with self.assertRaises(http.FetchError):
            guard(self.base + "/private")

    @unittest.skipUnless(os.environ.get("PLAYWRIGHT_BROWSERS_PATH"), "requires installed browser path")
    def test_browser_redirect_never_reaches_denied_target(self):
        with self.assertRaises(escalate.RenderError):
            escalate.render(self.base + "/public", settle_ms=0,
                            request_guard=self.guard)
        self.assertNotIn("/private", Handler.hits)
        self.assertEqual(Handler.hits, ["/public"])

    @unittest.skipUnless(os.environ.get("PLAYWRIGHT_BROWSERS_PATH"), "requires installed browser path")
    def test_browser_script_navigation_never_reaches_denied_target(self):
        escalate.render(self.base + "/navigate", settle_ms=500,
                        request_guard=self.guard)
        self.assertNotIn("/private", Handler.hits)
        self.assertIn("/navigate", Handler.hits)

    @unittest.skipUnless(os.environ.get("PLAYWRIGHT_BROWSERS_PATH"), "requires installed browser path")
    def test_browser_popup_never_reaches_denied_target(self):
        escalate.render(self.base + "/popup", settle_ms=500,
                        request_guard=self.guard)
        self.assertNotIn("/private", Handler.hits)
        self.assertIn("/popup", Handler.hits)

    @unittest.skipUnless(os.environ.get("PLAYWRIGHT_BROWSERS_PATH"), "requires installed browser path")
    def test_browser_script_request_never_reaches_denied_target(self):
        result = escalate.render(self.base + "/shell", settle_ms=500,
                                 request_guard=self.guard)
        self.assertEqual(result.status, 200)
        self.assertNotIn("/private", Handler.hits)
        self.assertIn("/shell", Handler.hits)
