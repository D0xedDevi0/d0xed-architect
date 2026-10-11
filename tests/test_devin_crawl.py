"""Bounded, robots-respecting public site map (mocked HTTP, no network)."""
import unittest

from devin.crawl_cmd import MapDenied, MapLimits, site_map
from tests.devin_fixtures import FakePublic, html_page


def seed(links):
    return (200, html_page("Example", links), "text/html")


class TestSiteMap(unittest.TestCase):
    def test_obeys_robots_and_stays_on_origin(self):
        pub = FakePublic({
            "https://example.com/": seed(["/a", "/b", "/secret",
                                          "https://other.com/x"]),
            "https://example.com/robots.txt": (
                200, b"User-agent: *\nDisallow: /secret\n", "text/plain"),
        })
        sm = site_map("https://example.com/", pub)
        self.assertEqual(sm.title, "Example")
        self.assertEqual(sm.robots, "found")
        self.assertEqual(sm.llms, "absent")
        urls = [u for u, _ in sm.internal_links]
        self.assertIn("https://example.com/a", urls)
        self.assertIn("https://example.com/b", urls)
        self.assertNotIn("https://example.com/secret", urls)   # robots-disallowed
        self.assertTrue(all(u.startswith("https://example.com/") for u in urls))

    def test_robots_404_is_absent_and_allows(self):
        pub = FakePublic({"https://example.com/": seed(["/a", "/secret"])})
        sm = site_map("https://example.com/", pub)
        self.assertEqual(sm.robots, "absent")
        urls = [u for u, _ in sm.internal_links]
        self.assertIn("https://example.com/secret", urls)

    def test_robots_unavailable_refuses(self):
        pub = FakePublic({
            "https://example.com/robots.txt": (500, b"boom", "text/plain")})
        with self.assertRaises(MapDenied):
            site_map("https://example.com/", pub)

    def test_robots_disallow_seed_refuses(self):
        pub = FakePublic({
            "https://example.com/robots.txt": (
                200, b"User-agent: *\nDisallow: /\n", "text/plain")})
        with self.assertRaises(MapDenied):
            site_map("https://example.com/", pub)

    def test_unsafe_url_refused(self):
        with self.assertRaises(MapDenied):
            site_map("http://127.0.0.1/", FakePublic())

    def test_non_200_seed_refused(self):
        pub = FakePublic({
            "https://example.com/robots.txt": (404, b"", "text/plain")})
        with self.assertRaises(MapDenied):
            site_map("https://example.com/", pub)

    def test_link_cap(self):
        pub = FakePublic({
            "https://example.com/": seed([f"/p{i}" for i in range(20)]),
            "https://example.com/robots.txt": (404, b"", "text/plain"),
        })
        sm = site_map("https://example.com/", pub, limits=MapLimits(max_links=5))
        self.assertEqual(len(sm.internal_links), 5)
        self.assertTrue(sm.links_capped)

    def test_llms_found(self):
        pub = FakePublic({
            "https://example.com/": seed([]),
            "https://example.com/robots.txt": (404, b"", "text/plain"),
            "https://example.com/llms.txt": (200, b"# llms", "text/plain"),
        })
        sm = site_map("https://example.com/", pub)
        self.assertEqual(sm.llms, "found")


if __name__ == "__main__":
    unittest.main()
