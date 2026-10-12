"""Per-origin crawl rules on redirects and browser resources."""
import unittest
from unittest.mock import patch

from architect import http
from architect.crawl_access import CrawlAccess


class CrawlAccessTests(unittest.TestCase):
    def setUp(self):
        self.policy = CrawlAccess("https://example.org", http.parse_robots(
            "User-agent: *\nDisallow: /private\n"))

    def test_same_origin_denial_and_query(self):
        with self.assertRaises(http.FetchError):
            self.policy.require("https://example.org/private?x=1")
        self.policy.require("https://example.org/public")

    def test_www_redirect_loads_its_own_rules_and_reuses_them(self):
        r = http.Response(url="https://www.example.org/robots.txt", status=200,
                          headers={}, body=b"User-agent: *\nDisallow: /blocked\n")
        with patch.object(http, "fetch", return_value=r) as fetch:
            self.policy.require("https://www.example.org/public")
            with self.assertRaises(http.FetchError):
                self.policy.require("https://www.example.org/blocked")
        self.assertEqual(fetch.call_count, 1)

    def test_other_site_and_https_downgrade_refused_before_loading_policy(self):
        with patch.object(http, "fetch") as fetch:
            for url in ("https://other.org/public", "http://example.org/public",
                        "https://www.example.org:9999/public"):
                with self.assertRaises(http.FetchError):
                    self.policy.require(url)
            fetch.assert_not_called()

    def test_non_404_robots_failure_on_www_fails_closed(self):
        r = http.Response(url="https://www.example.org/robots.txt", status=503,
                          headers={}, body=b"")
        with patch.object(http, "fetch", return_value=r):
            with self.assertRaises(http.FetchError):
                self.policy.require("https://www.example.org/public")

    def test_www_404_cannot_override_initial_origin_disallow(self):
        r = http.Response(url="https://www.example.org/robots.txt", status=404,
                          headers={}, body=b"")
        with patch.object(http, "fetch", return_value=r):
            with self.assertRaises(http.FetchError):
                self.policy.require("https://www.example.org/private")

    def test_ambiguous_path_normalization_denied(self):
        for path in ("/%2e%2e/private", "//private", "/foo/../private",
                     "/%252e%252e/private", "/%2fprivate"):
            with self.subTest(path=path):
                with self.assertRaises(http.FetchError):
                    self.policy.require("https://example.org" + path)

    def test_parallel_new_origin_does_not_block_base_policy(self):
        import threading
        started = threading.Event()
        release = threading.Event()
        r = http.Response(url="https://www.example.org/robots.txt", status=404,
                          headers={}, body=b"")
        def slow_fetch(*args, **kwargs):
            started.set()
            release.wait(timeout=2)
            return r
        with patch.object(http, "fetch", side_effect=slow_fetch):
            worker = threading.Thread(target=self.policy.require,
                args=("https://www.example.org/public",))
            worker.start()
            try:
                self.assertTrue(started.wait(timeout=1))
                finished = threading.Event()
                other = threading.Thread(target=lambda: (
                    self.policy.require("https://example.org/public"),
                    finished.set()))
                other.start()
                self.assertTrue(finished.wait(timeout=0.5),
                    "base-origin check blocked by unrelated robots discovery")
                other.join(timeout=2)
            finally:
                release.set()
                worker.join(timeout=2)

    def test_primary_robots_non_404_fails_closed(self):
        r = http.Response(url="https://example.org/robots.txt", status=503,
                          headers={}, body=b"")
        with patch.object(http, "fetch", return_value=r):
            with self.assertRaises(http.FetchError):
                http.load_robots("https://example.org", strict=True)

    def test_primary_robots_404_is_explicitly_absent(self):
        r = http.Response(url="https://example.org/robots.txt", status=404,
                          headers={}, body=b"")
        with patch.object(http, "fetch", return_value=r):
            self.assertFalse(http.load_robots("https://example.org", strict=True).found)

    def test_404_robots_on_www_allows_navigation(self):
        r = http.Response(url="https://www.example.org/robots.txt", status=404,
                          headers={}, body=b"")
        with patch.object(http, "fetch", return_value=r):
            self.policy.require("https://www.example.org/public")
