"""Deep links, /start payloads, and the crawl/sitemap/link commands.

The linking layer exists so a human can point DEVin at anything; it must never
become a way to smuggle instructions into the bot. So a deep-link payload is
only ever a KEY into a fixed table of sentences — it cannot carry a URL, a
command, or a token, and an invalid payload is dropped rather than echoed.
"""
import unittest

from devin import report
from devin.bot import DevinBot
from devin.commands import COMMANDS, MAX_DEPTH, parse_command
from devin.config import Config, Limits
from devin.report import (DEEPLINK_PAYLOADS, START_TEXT, render_link,
                          render_start)
from tests.devin_fixtures import (BOT_USERNAME, FAKE_TOKEN, GROUP_ID, USER_ID,
                                  FakeGithub, FakePublic, FakeTelegram,
                                  build_tarball, dm_update, html_page)


def make_bot(tg=None, public_fetch=None):
    cfg = Config(token=FAKE_TOKEN, allowed_user_ids=(USER_ID,),
                 allowed_group_ids=(GROUP_ID,), limits=Limits(),
                 bot_id=None, bot_username=BOT_USERNAME)
    tg = tg or FakeTelegram()
    gh = FakeGithub(tarball=build_tarball({"a.py": b"x = 1\n"}))
    return DevinBot(cfg, tg, gh, public_fetch), tg


SITE = {
    "https://example.com/robots.txt": (200, b"User-agent: *\nAllow: /", "text/plain"),
    "https://example.com/": (200, html_page("Ex", ["/a", "/b"]), "text/html"),
    "https://example.com/a": (200, html_page("A", ["/"]), "text/html"),
    "https://example.com/b": (200, html_page("B", []), "text/html"),
    "https://example.com/sitemap.xml": (
        200, b"<urlset><url><loc>https://example.com/p1</loc></url></urlset>",
        "application/xml"),
}


class TestStartPayload(unittest.TestCase):
    def test_plain_start_has_no_payload(self):
        self.assertEqual(parse_command("/start", 500).arg, None)
        self.assertEqual(render_start(None), START_TEXT)

    def test_known_payload_selects_a_hint(self):
        cmd = parse_command("/start audit", 500)
        self.assertEqual(cmd.kind, "start")
        self.assertEqual(cmd.arg, "audit")
        out = render_start("audit")
        self.assertIn(DEEPLINK_PAYLOADS["audit"], out)
        self.assertIn("Looper #706", out)
        self.assertLessEqual(len(out), 1024)          # telegram caption cap

    def test_unknown_payload_is_ignored_not_echoed(self):
        self.assertEqual(render_start("bogus"), START_TEXT)

    def test_hostile_payloads_are_dropped(self):
        for bad in ("../../../etc/passwd", "<script>alert(1)</script>",
                    "audit;rm -rf /", "x" * 200, "a/b", "..", "%%%"):
            with self.subTest(bad=bad):
                self.assertIsNone(parse_command(f"/start {bad}", 500).arg)

    def test_payload_with_bot_mention_suffix(self):
        cmd = parse_command(f"/start@Bot crawl", 500)
        self.assertEqual(cmd.kind, "start")
        self.assertEqual(cmd.arg, "crawl")

    def test_every_deeplink_payload_renders_bounded(self):
        for key in DEEPLINK_PAYLOADS:
            out = render_start(key)
            self.assertLessEqual(len(out), 1024, key)
            self.assertIn("Looper #706", out, key)

    def test_start_dispatch_reports_the_payload(self):
        bot, tg = make_bot()
        r = bot.handle_update(dm_update(1, USER_ID, "/start crawl"))
        self.assertEqual(r.detail, "start:crawl")
        self.assertIn(DEEPLINK_PAYLOADS["crawl"], tg.photos[0]["caption"])

    def test_start_dispatch_without_payload(self):
        bot, tg = make_bot()
        r = bot.handle_update(dm_update(1, USER_ID, "/start"))
        self.assertEqual(r.detail, "start:-")


class TestLinkCommand(unittest.TestCase):
    def test_render_link_uses_the_live_username(self):
        out = render_link("somebot")
        self.assertIn("https://t.me/somebot", out)
        self.assertIn("?start=audit", out)
        self.assertIn("?startgroup=true", out)
        self.assertIn("/audit@somebot", out)

    def test_render_link_falls_back_without_username(self):
        out = render_link(None)
        self.assertIn("https://t.me/DEVinlooperbot", out)

    def test_render_link_never_leaks_a_token(self):
        out = render_link(BOT_USERNAME)
        self.assertNotIn(FAKE_TOKEN, out)
        for word in ("token", "api_key", "secret"):
            self.assertNotIn(word, out.lower())

    def test_link_command_replies(self):
        bot, tg = make_bot()
        r = bot.handle_update(dm_update(1, USER_ID, "/link"))
        self.assertEqual(r.action, "replied")
        self.assertEqual(r.detail, "link")
        self.assertIn("https://t.me/", tg.sent[0]["text"])

    def test_link_is_a_no_arg_command(self):
        self.assertEqual(parse_command("/link", 500).kind, "link")
        self.assertEqual(parse_command("/link extra", 500).kind, "link")


class TestCrawlCommand(unittest.TestCase):
    def test_crawl_parsing(self):
        self.assertEqual(parse_command("/crawl https://a.test 2", 500).depth, 2)
        self.assertEqual(parse_command("/crawl https://a.test", 500).depth, None)
        for bad in (f"/crawl https://a.test {MAX_DEPTH + 1}",
                    "/crawl https://a.test 0", "/crawl https://a.test abc",
                    "/crawl https://a.test 1 2", "/crawl"):
            with self.subTest(bad=bad):
                self.assertEqual(parse_command(bad, 500).kind, "reject", bad)

    def test_crawl_runs_through_the_bot(self):
        bot, tg = make_bot(public_fetch=FakePublic(SITE))
        r = bot.handle_update(dm_update(1, USER_ID,
                                        "/crawl https://example.com/ 2"))
        self.assertEqual(r.action, "replied")
        self.assertTrue(r.detail.startswith("crawl:"), r.detail)
        self.assertIn("top pages", tg.sent[0]["text"])

    def test_crawl_refusal_is_in_voice(self):
        # robots.txt answering 5xx means the policy is UNKNOWN -> refuse.
        # An empty site is NOT a refusal: a 404 robots is "no policy".
        site = {"https://example.com/robots.txt": (500, b"", "text/plain")}
        bot, tg = make_bot(public_fetch=FakePublic(site))
        r = bot.handle_update(dm_update(1, USER_ID,
                                        "/crawl https://example.com/ 2"))
        self.assertEqual(r.detail, "crawl-denied")
        self.assertIn("refused", tg.sent[0]["text"])

    def test_missing_robots_is_not_a_refusal(self):
        site = {"https://example.com/": (200, html_page("Ex", []), "text/html")}
        bot, tg = make_bot(public_fetch=FakePublic(site))
        r = bot.handle_update(dm_update(1, USER_ID, "/crawl https://example.com/"))
        self.assertTrue(r.detail.startswith("crawl:"), r.detail)
        self.assertIn("robots: absent", tg.sent[0]["text"])

    def test_crawl_never_leaves_the_origin(self):
        site = dict(SITE)
        site["https://example.com/"] = (
            200, html_page("Ex", ["https://evil.test/x", "/a"]), "text/html")
        pub = FakePublic(site)
        bot, _tg = make_bot(public_fetch=pub)
        bot.handle_update(dm_update(1, USER_ID, "/crawl https://example.com/ 2"))
        asked = [u for u, _t in pub.requests] if hasattr(pub, "requests") else []
        for url in asked:
            self.assertTrue(url.startswith("https://example.com/"), url)


class TestSitemapCommand(unittest.TestCase):
    def test_sitemap_runs_through_the_bot(self):
        bot, tg = make_bot(public_fetch=FakePublic(SITE))
        r = bot.handle_update(dm_update(1, USER_ID, "/sitemap https://example.com/"))
        self.assertEqual(r.action, "replied")
        self.assertTrue(r.detail.startswith("sitemap:"), r.detail)
        self.assertIn("https://example.com/p1", tg.sent[0]["text"])

    def test_sitemap_without_one_is_honest(self):
        site = {k: v for k, v in SITE.items() if "sitemap" not in k}
        bot, tg = make_bot(public_fetch=FakePublic(site))
        r = bot.handle_update(dm_update(1, USER_ID, "/sitemap https://example.com/"))
        self.assertTrue(r.detail.startswith("sitemap:"), r.detail)
        self.assertIn("no sitemap URLs found", tg.sent[0]["text"])

    def test_sitemap_requires_one_argument(self):
        self.assertEqual(parse_command("/sitemap", 500).kind, "reject")


class TestMenuSingleSource(unittest.TestCase):
    def test_registered_commands_and_menu_agree(self):
        """The Telegram menu, the parser, and the dispatcher must not drift."""
        menu = [c["command"] for c in report.COMMANDS]
        self.assertEqual(set(menu), {c[1:] for c in COMMANDS})

    def test_help_mentions_every_command(self):
        help_text = report.render_help()
        for name in COMMANDS:
            self.assertIn(name, help_text, f"{name} missing from /help")

    def test_start_mentions_every_other_command(self):
        # /start is the banner; it cannot list itself.
        for name in COMMANDS:
            if name == "/start":
                continue
            self.assertIn(name, START_TEXT, f"{name} missing from /start")

    def test_every_command_is_documented_or_intentionally_short(self):
        # /start is the banner itself; everything else must appear in the menu.
        menu = {c["command"] for c in report.COMMANDS}
        self.assertEqual(menu - {"start"}, {c[1:] for c in COMMANDS} - {"start"})


if __name__ == "__main__":
    unittest.main()
