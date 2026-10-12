"""Crawler v2: bounds, robots enforcement, link graph, assets, sitemaps.

Every test here pins a safety property, not a formatting detail:
  * robots.txt is honored on EVERY url and fails CLOSED
  * the crawl never leaves the seed origin, even when a page links out
  * every budget (pages, depth, bytes, time) actually stops the crawl
  * a sitemap cannot expand entities (billion laughs / XXE)
  * nothing raises out of the crawler for hostile input
"""
import hashlib
import unittest
import urllib.parse

from devin.crawl2 import (CrawlDenied, CrawlLimits, asset_kind, crawl_site,
                          discover_sitemaps, norm_url, render_crawl,
                          render_sitemap, sitemap_inventory, sitemap_urls)

ALLOW_ALL = "User-agent: *\nAllow: /"


class Resp:
    def __init__(self, url, status, body, content_type="text/html; charset=utf-8"):
        self.url = url
        self.status = status
        self.body = body.encode("utf-8") if isinstance(body, str) else body
        self.content_type = content_type

    @property
    def text(self):
        return self.body.decode("utf-8", "replace")


class FakeSite:
    """A tiny site served from a dict. Records every URL fetched so the tests
    can prove the crawler did not touch anything it should not have."""

    def __init__(self, base="https://ex.test", pages=None, robots=ALLOW_ALL,
                 robots_status=200, sitemaps=None,
                 content_type="text/html; charset=utf-8"):
        self.base = base
        self.pages = pages or {}
        self.robots = robots
        self.robots_status = robots_status
        self.sitemaps = sitemaps or {}
        self.content_type = content_type
        self.calls = []

    def __call__(self, url, timeout=None):
        self.calls.append(url)
        if urllib.parse.urlsplit(url).path == "/robots.txt":
            if self.robots is None:
                return Resp(url, 404, "no robots", "text/plain")
            return Resp(url, self.robots_status, self.robots, "text/plain")
        if url in self.sitemaps:
            return Resp(url, 200, self.sitemaps[url], "application/xml")
        path = urllib.parse.urlsplit(url).path
        if path in self.pages:
            return Resp(url, 200, self.pages[path], self.content_type)
        return Resp(url, 404, "not found")


def page(title="t", links=()):
    anchors = "".join(f'<a href="{h}">{h}</a>' for h in links)
    return f"<html><head><title>{title}</title></head><body>{anchors}</body></html>"


class TestFetchSafety(unittest.TestCase):
    def test_unsafe_urls_are_refused(self):
        for bad in ("file:///etc/passwd", "http://127.0.0.1/",
                    "http://169.254.169.254/latest/meta-data/",
                    "http://localhost:8080/", "gopher://x/1"):
            with self.subTest(bad=bad):
                with self.assertRaises(CrawlDenied):
                    crawl_site(bad, FakeSite())

    def test_absent_robots_is_allowed(self):
        """404 means 'no policy' -> allow all. Anything ELSE (5xx/403/timeout)
        means 'policy unknown' -> refuse, because guessing here would crawl a
        site that never consented."""
        rep = crawl_site("https://ex.test/", FakeSite(robots=None,
                                                     pages={"/": page()}))
        self.assertEqual(rep.robots, "absent")

    def test_unavailable_robots_fails_closed(self):
        for status in (500, 502, 403, 429, 401):
            with self.subTest(status=status):
                with self.assertRaises(CrawlDenied):
                    crawl_site("https://ex.test/",
                               FakeSite(robots_status=status, pages={"/": page()}))

    def test_robots_timeout_fails_closed(self):
        class Boom(FakeSite):
            def __call__(self, url, timeout=None):
                if urllib.parse.urlsplit(url).path == "/robots.txt":
                    raise TimeoutError("no answer")
                return super().__call__(url, timeout)

        with self.assertRaises(CrawlDenied):
            crawl_site("https://ex.test/", Boom(pages={"/": page()}))

    def test_seed_disallowed_by_robots_is_refused(self):
        site = FakeSite(robots="User-agent: *\nDisallow: /priv",
                        pages={"/priv": page()})
        with self.assertRaises(CrawlDenied):
            crawl_site("https://ex.test/priv", site)


class TestCrawlBounds(unittest.TestCase):
    def test_depth_is_respected(self):
        site = FakeSite(pages={"/a": page(links=["/b"]),
                               "/b": page(links=["/c"]),
                               "/c": page(links=["/d"]),
                               "/d": page()})
        rep = crawl_site("https://ex.test/a", site,
                         CrawlLimits(max_depth=1, max_pages=20))
        self.assertEqual([p.url for p in rep.pages],
                         ["https://ex.test/a", "https://ex.test/b"])

    def test_full_depth_walks_the_chain(self):
        site = FakeSite(pages={"/a": page(links=["/b"]),
                               "/b": page(links=["/c"]),
                               "/c": page()})
        rep = crawl_site("https://ex.test/a", site,
                         CrawlLimits(max_depth=3, max_pages=20))
        self.assertEqual(len(rep.pages), 3)
        self.assertFalse(rep.truncated)

    def test_page_budget_stops_and_flags(self):
        site = FakeSite(pages={"/a": page(links=["/b", "/c", "/d"]),
                               "/b": page(links=["/e"]), "/c": page(),
                               "/d": page(), "/e": page()})
        rep = crawl_site("https://ex.test/a", site,
                         CrawlLimits(max_pages=2, max_depth=3))
        self.assertEqual(len(rep.pages), 2)
        self.assertTrue(rep.truncated)

    def test_byte_budget_stops(self):
        def big(links=()):
            anchors = "".join(f'<a href="{h}">x</a>' for h in links)
            return "<html><body>" + anchors + ("x" * 5000) + "</body></html>"

        site = FakeSite(pages={"/a": big(["/b", "/c"]),
                               "/b": big(["/c"]), "/c": big()})
        rep = crawl_site("https://ex.test/a", site,
                         CrawlLimits(max_pages=10, max_depth=3,
                                     max_page_bytes=10_000,
                                     max_total_bytes=6_000))
        self.assertLessEqual(len(rep.pages), 2)
        self.assertTrue(rep.truncated)
        self.assertTrue(any("byte budget" in r for _u, r in rep.skipped))

    def test_time_budget_stops(self):
        site = FakeSite(pages={"/a": page(links=["/b", "/c", "/d"]),
                               "/b": page(), "/c": page(), "/d": page()})
        ticks = iter([0.0, 0.0, 0.0, 99.0, 99.0, 99.0, 99.0])
        rep = crawl_site("https://ex.test/a", site,
                         CrawlLimits(max_pages=9, max_depth=2, deadline_s=10.0),
                         clock=lambda: next(ticks, 99.0))
        self.assertTrue(rep.truncated)

    def test_oversized_page_is_skipped_not_read(self):
        site = FakeSite(pages={"/a": "<html>" + "y" * 9000 + "</html>"},
                        content_type="text/html")
        rep = crawl_site("https://ex.test/a", site,
                         CrawlLimits(max_page_bytes=1000))
        self.assertEqual(rep.pages[0].error, "page too large")


class TestOriginDiscipline(unittest.TestCase):
    def test_never_fetches_off_origin(self):
        site = FakeSite(pages={
            "/a": page(links=["https://other.test/x", "/b",
                              "https://ex.test:8443/c", "//cdn.test/z"]),
            "/b": page(),
        })
        rep = crawl_site("https://ex.test/a", site,
                         CrawlLimits(max_depth=2, max_pages=10))
        for url in site.calls:
            self.assertTrue(url.startswith("https://ex.test/"),
                            f"fetched off-origin: {url}")
        self.assertNotIn("https://other.test/x", site.calls)
        self.assertIn("other.test", rep.external_hosts)

    def test_www_hop_is_a_different_origin(self):
        site = FakeSite(pages={"/a": page(links=["https://www.ex.test/b"])})
        rep = crawl_site("https://ex.test/a", site)
        self.assertIn("www.ex.test", rep.external_hosts)
        self.assertEqual(len(rep.pages), 1)

    def test_robots_disallowed_link_is_dropped_before_fetch(self):
        site = FakeSite(robots="User-agent: *\nAllow: /\nDisallow: /private",
                        pages={"/a": page(links=["/private/x", "/b"]),
                               "/b": page(), "/private/x": page()})
        rep = crawl_site("https://ex.test/a", site,
                         CrawlLimits(max_depth=2, max_pages=10))
        self.assertNotIn("https://ex.test/private/x", site.calls)
        self.assertIn(("https://ex.test/private/x", "robots-disallowed"),
                      rep.skipped)

    def test_fragment_and_port_variants_dedupe(self):
        site = FakeSite(pages={"/a": page(links=["/b#top", "/b",
                                                 "https://ex.test:443/b"])})
        rep = crawl_site("https://ex.test/a", site,
                         CrawlLimits(max_depth=2, max_pages=10))
        self.assertEqual([p.url for p in rep.pages],
                         ["https://ex.test/a", "https://ex.test/b"])


class TestProvenanceAndGraph(unittest.TestCase):
    def test_receipts_are_real_hashes_of_the_body(self):
        site = FakeSite(pages={"/a": page(links=["/b"]), "/b": page()})
        rep = crawl_site("https://ex.test/a", site,
                         CrawlLimits(max_depth=2, max_pages=5))
        for p in rep.pages:
            self.assertEqual(len(p.sha256), 64)
        body = site.pages["/b"].encode("utf-8")
        receipt = [p for p in rep.pages if p.url.endswith("/b")][0]
        self.assertEqual(receipt.sha256, hashlib.sha256(body).hexdigest())
        self.assertEqual(receipt.bytes, len(body))

    def test_in_degree_finds_the_hub(self):
        site = FakeSite(pages={
            "/a": page(links=["/hub", "/x", "/y"]),
            "/x": page(links=["/hub"]), "/y": page(links=["/hub"]),
            "/hub": page(),
        })
        rep = crawl_site("https://ex.test/a", site,
                         CrawlLimits(max_depth=2, max_pages=10))
        self.assertEqual(rep.in_degree()["https://ex.test/hub"], 3)
        self.assertEqual(rep.top_pages(1)[0].url, "https://ex.test/hub")

    def test_assets_are_inventoried_by_kind(self):
        site = FakeSite(pages={"/a": page(links=[
            "/style.css", "/app.js", "/logo.png", "/font.woff2",
            "/doc.pdf", "/data.json", "/b"])})
        rep = crawl_site("https://ex.test/a", site)
        kinds = rep.asset_kinds()
        self.assertEqual(kinds["script"], 1)
        self.assertEqual(kinds["style"], 1)
        self.assertEqual(kinds["image"], 1)
        self.assertEqual(kinds["font"], 1)
        self.assertEqual(kinds["document"], 1)
        self.assertEqual(kinds["data"], 1)

    def test_non_200_link_is_recorded_not_raised(self):
        site = FakeSite(pages={"/a": page(links=["/missing"])})
        rep = crawl_site("https://ex.test/a", site,
                         CrawlLimits(max_depth=2, max_pages=5))
        by = {p.url.rsplit("/", 1)[-1]: p for p in rep.pages}
        self.assertEqual(by["a"].error, "")           # the seed is fine
        self.assertEqual(by["missing"].status, 404)
        self.assertIn("404", by["missing"].error)
        self.assertIn(by["missing"], rep.errors())

    def test_undecodable_body_does_not_crash_the_crawl(self):
        """A body that will not decode is data, not an exception. This is the
        shape that used to escape sitemap_inventory as a 500."""
        class Blob:
            def __init__(self, url, status=200,
                         content_type="text/html; charset=x-user-defined"):
                self.url, self.status, self.body = url, status, b"\xff\xfe\x00\x01html"
                self.content_type = content_type

            @property
            def text(self):        # a lazy property that raises, like a bad decode
                raise UnicodeDecodeError("utf-8", b"\xff", 0, 1, "bad")

        class BlobSite(FakeSite):
            def __call__(self, url, timeout=None):
                if urllib.parse.urlsplit(url).path == "/robots.txt":
                    return Blob(url, content_type="text/plain")
                if url.endswith(".xml"):
                    return Blob(url, content_type="application/xml")
                return Blob(url)

        rep = crawl_site("https://ex.test/a", BlobSite())
        self.assertEqual(len(rep.pages), 1)      # recorded, no raise
        origin, fetched, urls, _nested = sitemap_inventory("https://ex.test/",
                                                           BlobSite())
        self.assertEqual(origin, "https://ex.test")
        self.assertEqual(urls, [])

    def test_non_html_response_is_skipped(self):
        site = FakeSite(pages={"/a": "binary-ish"}, content_type="image/png")
        rep = crawl_site("https://ex.test/a", site)
        self.assertEqual(rep.pages[0].error, "not html")

    def test_title_and_description_are_captured(self):
        site = FakeSite(pages={"/a":
                               '<html><head><title>Hi there</title>'
                               '<meta name="description" content="desc here">'
                               "</head><body></body></html>"})
        rep = crawl_site("https://ex.test/a", site)
        self.assertEqual(rep.pages[0].title, "Hi there")
        self.assertEqual(rep.pages[0].description, "desc here")

    def test_deterministic_across_runs(self):
        pages = {"/a": page(links=["/b", "/c", "/d"]), "/b": page(links=["/e"]),
                 "/c": page(), "/d": page(), "/e": page()}
        one = crawl_site("https://ex.test/a", FakeSite(pages=pages),
                         CrawlLimits(max_depth=2, max_pages=10))
        two = crawl_site("https://ex.test/a", FakeSite(pages=pages),
                         CrawlLimits(max_depth=2, max_pages=10))
        self.assertEqual([p.url for p in one.pages], [p.url for p in two.pages])
        self.assertEqual(one.edges, two.edges)
        self.assertEqual(one.assets, two.assets)

    def test_render_is_bounded(self):
        site = FakeSite(pages={"/a": page(title="T" * 300,
                                          links=["/b", "/c"])})
        rep = crawl_site("https://ex.test/a", site)
        self.assertLessEqual(len(render_crawl(rep, max_len=120)), 120)


class TestSitemaps(unittest.TestCase):
    def test_loc_extraction(self):
        xml = ("<urlset><url><loc>https://ex.test/p1</loc></url>"
               "<url><loc>https://ex.test/p2</loc></url></urlset>")
        self.assertEqual(sitemap_urls(xml), ["https://ex.test/p1",
                                             "https://ex.test/p2"])

    def test_entity_bearing_xml_is_refused(self):
        evil = ('<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol">]>'
                "<urlset><url><loc>&lol;</loc></url></urlset>")
        self.assertEqual(sitemap_urls(evil), [])

    def test_malformed_xml_falls_back_to_regex(self):
        xml = "<urlset><url><loc>https://ex.test/p1</loc></urlset>"
        self.assertEqual(sitemap_urls(xml), ["https://ex.test/p1"])

    def test_robots_sitemap_hint_is_used(self):
        hints = discover_sitemaps("https://ex.test",
                                  "User-agent: *\nSitemap: /sm.xml\n", None, 5.0)
        self.assertIn("https://ex.test/sm.xml", hints)
        self.assertIn("https://ex.test/sitemap.xml", hints)   # guess

    def test_inventory_reads_index_and_pages(self):
        index = ("<sitemapindex><sitemap><loc>https://ex.test/sm1.xml</loc>"
                 "</sitemap></sitemapindex>")
        child = ("<urlset><url><loc>https://ex.test/p1</loc></url>"
                 "<url><loc>https://ex.test/p2</loc></url></urlset>")
        site = FakeSite(robots="User-agent: *\nSitemap: https://ex.test/sm.xml",
                        sitemaps={"https://ex.test/sm.xml": index,
                                  "https://ex.test/sm1.xml": child})
        origin, fetched, urls, nested = sitemap_inventory("https://ex.test/", site)
        self.assertEqual(origin, "https://ex.test")
        self.assertIn("https://ex.test/sm.xml", fetched)
        self.assertIn("https://ex.test/sm1.xml", fetched)
        self.assertEqual(urls, ["https://ex.test/p1", "https://ex.test/p2"])

    def test_inventory_ignores_off_origin_locs(self):
        xml = ("<urlset><url><loc>https://evil.test/x</loc></url>"
               "<url><loc>https://ex.test/ok</loc></url></urlset>")
        site = FakeSite(sitemaps={"https://ex.test/sitemap.xml": xml})
        _origin, _f, urls, _n = sitemap_inventory("https://ex.test/", site)
        self.assertEqual(urls, ["https://ex.test/ok"])

    def test_render_sitemap_reports_absence(self):
        out = render_sitemap("https://ex.test", [], [], [])
        self.assertIn("no sitemap URLs found", out)


class TestHelpers(unittest.TestCase):
    def test_norm_url(self):
        self.assertEqual(norm_url("https://ex.test:443/a#f"), "https://ex.test/a")
        self.assertEqual(norm_url("http://EX.test:80/a?b=1"),
                         "http://ex.test/a?b=1")
        self.assertEqual(norm_url("https://ex.test"), "https://ex.test/")

    def test_asset_kind(self):
        self.assertEqual(asset_kind("https://x/a/b.PNG"), "image")
        self.assertEqual(asset_kind("https://x/a.js?v=1"), "script")
        self.assertEqual(asset_kind("https://x/page"), "")


if __name__ == "__main__":
    unittest.main()
