"""Bot dispatch: allowlist gating, bounded commands, token never echoed."""
import unittest

from devin.bot import DevinBot, TelegramError
from devin.commands import COMMANDS
from devin.config import Config, Limits
from devin.report import PHOTO
from tests.devin_fixtures import (BOT_ID, BOT_USERNAME, FAKE_TOKEN, GROUP_ID,
                                  USER_ID, FakeGithub, FakeTelegram,
                                  build_tarball, dm_update, group_update)


def make_bot(gh=None, tg=None, groups=(GROUP_ID,), github_token=None,
             public_fetch=None):
    cfg = Config(token=FAKE_TOKEN, allowed_user_ids=(USER_ID,),
                 allowed_group_ids=groups, limits=Limits(),
                 bot_id=BOT_ID, bot_username=BOT_USERNAME,
                 github_token=github_token)
    gh = gh or FakeGithub(tarball=build_tarball({"src/app.py": b"x = 1\n"}))
    tg = tg or FakeTelegram()
    return DevinBot(cfg, tg, gh, public_fetch), gh, tg


class TestBotCommands(unittest.TestCase):
    def test_start(self):
        bot, _, tg = make_bot()
        r = bot.handle_update(dm_update(1, USER_ID, "/start"))
        self.assertEqual(r.action, "replied")
        self.assertEqual(r.detail, "start")
        # /start opens with Looper #706's art + the welcome caption
        self.assertEqual(tg.photos[0]["photo"], PHOTO)
        self.assertIn("/audit", tg.photos[0]["caption"])
        self.assertEqual(tg.sent, [])       # no separate text message

    def test_help(self):
        bot, _, tg = make_bot()
        r = bot.handle_update(dm_update(1, USER_ID, "/help"))
        self.assertEqual(r.detail, "help")
        self.assertIn("/audit", tg.sent[0]["text"])

    def test_audit_authorized(self):
        bot, gh, tg = make_bot()
        r = bot.handle_update(dm_update(1, USER_ID,
                                        "/audit https://github.com/owner/repo"))
        self.assertEqual(r.action, "replied")
        self.assertTrue(r.detail.startswith("audit:owner/repo"))
        text = tg.sent[0]["text"]
        self.assertIn("STATIC-ONLY", text)
        self.assertIn("manifest:", text)
        # audit fetched only from allowlisted GitHub hosts
        self.assertEqual(len(gh.calls), 2)

    def test_audit_denied_for_bad_url(self):
        bot, gh, tg = make_bot()
        r = bot.handle_update(dm_update(1, USER_ID,
                                        "/audit https://example.com/a/b"))
        self.assertEqual(r.detail, "audit-denied")
        self.assertIn("audit refused", tg.sent[0]["text"])
        self.assertEqual(gh.calls, [])

    def test_unknown_command_rejected(self):
        bot, _, tg = make_bot()
        r = bot.handle_update(dm_update(1, USER_ID, "/rm -rf /"))
        self.assertEqual(r.action, "replied")
        self.assertTrue(r.detail.startswith("reject:"))
        self.assertIn("Allowed:", tg.sent[0]["text"])

    def test_command_coverage_every_registered_command_dispatches(self):
        # A handler must exist for every registered command (no dead code).
        bot, _, _ = make_bot()
        expectations = {
            "/start": "start",
            "/help": "help",
            "/lore": "lore",
            "/doctor": "doctor",
        }
        for cmd, expected in expectations.items():
            r = bot.handle_update(dm_update(1, USER_ID, cmd))
            self.assertEqual(r.detail, expected, cmd)
        self.assertEqual(COMMANDS,
                         ("/start", "/help", "/lore", "/audit", "/debug",
                          "/map", "/doctor"))
        # /audit and /debug are exercised here; /map needs an injected fetcher.
        r = bot.handle_update(dm_update(2, USER_ID, "/audit https://github.com/a/b"))
        self.assertTrue(r.detail.startswith("audit:"), r.detail)
        r = bot.handle_update(dm_update(3, USER_ID, "/debug https://github.com/a/b"))
        self.assertTrue(r.detail.startswith("debug:"), r.detail)


class TestNewCommands(unittest.TestCase):
    def test_lore_authorized(self):
        bot, _, tg = make_bot()
        r = bot.handle_update(dm_update(1, USER_ID, "/lore"))
        self.assertEqual(r.detail, "lore")
        text = tg.sent[0]["text"]
        self.assertIn("Looper #706", text)
        self.assertIn("87226", text)
        self.assertIn("Wire a tool", text)

    def test_start_falls_back_to_text_when_photo_rejected(self):
        tg = FakeTelegram(photo_ok=False)
        bot, _, tg = make_bot(tg=tg)
        r = bot.handle_update(dm_update(1, USER_ID, "/start"))
        self.assertEqual(r.detail, "start")
        self.assertEqual(len(tg.photos), 1)           # photo was attempted
        self.assertIn("/audit", tg.sent[0]["text"])   # text fallback landed

    def test_debug_authorized(self):
        bot, gh, tg = make_bot()
        r = bot.handle_update(dm_update(1, USER_ID,
                                        "/debug https://github.com/owner/repo"))
        self.assertEqual(r.action, "replied")
        self.assertTrue(r.detail.startswith("debug:owner/repo"))
        self.assertIn("STATIC-ONLY", tg.sent[0]["text"])

    def test_doctor_authorized(self):
        bot, _, tg = make_bot()
        r = bot.handle_update(dm_update(1, USER_ID, "/doctor"))
        self.assertEqual(r.detail, "doctor")
        text = tg.sent[0]["text"]
        self.assertIn("self-diagnostics", text)
        self.assertNotIn(FAKE_TOKEN, text)

    def test_map_authorized(self):
        from tests.devin_fixtures import FakePublic, html_page
        pub = FakePublic({"https://example.com/": (
            200, html_page("Example", ["/a"]), "text/html")})
        bot, _, tg = make_bot(public_fetch=pub)
        r = bot.handle_update(dm_update(1, USER_ID, "/map https://example.com/"))
        self.assertEqual(r.action, "replied")
        self.assertTrue(r.detail.startswith("map:"))
        self.assertIn("site map", tg.sent[0]["text"])

    def test_map_without_fetcher_is_unavailable(self):
        bot, _, tg = make_bot(public_fetch=None)
        r = bot.handle_update(dm_update(1, USER_ID, "/map https://example.com/"))
        self.assertEqual(r.detail, "map-unavailable")

    def test_group_debug_mention_runs(self):
        bot, gh, tg = make_bot()
        r = bot.handle_update(group_update(
            9, USER_ID, GROUP_ID, f"/debug@{BOT_USERNAME} https://github.com/o/r"))
        self.assertTrue(r.detail.startswith("debug:o/r"))

    def test_group_doctor_bare_is_ignored(self):
        bot, _, tg = make_bot()
        r = bot.handle_update(group_update(9, USER_ID, GROUP_ID, "/doctor"))
        self.assertEqual(r.action, "ignored")
        self.assertEqual(tg.sent, [])


class TestBotAccess(unittest.TestCase):
    def test_unauthorized_private_sender_rejected(self):
        bot, gh, tg = make_bot()
        r = bot.handle_update(dm_update(1, 999999, "/audit https://github.com/a/b"))
        self.assertEqual(r.action, "denied")
        self.assertEqual(r.detail, "sender not allowlisted")
        self.assertEqual(tg.sent[0]["text"], "Not on the list.")
        self.assertEqual(gh.calls, [])   # no audit was run

    def test_unauthorized_group_silent(self):
        bot, gh, tg = make_bot()
        r = bot.handle_update(group_update(2, USER_ID, -111, "/help"))
        self.assertEqual(r.action, "denied")
        self.assertEqual(tg.sent, [])    # no reply, no amplification


class TestGroupAddressing(unittest.TestCase):
    """Shared-group etiquette: several bots share one room, so reply only when
    explicitly addressed — via /cmd@BotName mention or a reply to the bot."""

    def test_bare_command_in_group_is_ignored(self):
        bot, gh, tg = make_bot()
        r = bot.handle_update(group_update(3, USER_ID, GROUP_ID, "/help"))
        self.assertEqual(r.action, "ignored")
        self.assertEqual(tg.sent, [])          # silent: no cross-bot spam

    def test_mention_command_in_group_is_served(self):
        bot, gh, tg = make_bot()
        r = bot.handle_update(group_update(
            3, USER_ID, GROUP_ID, f"/help@{BOT_USERNAME}"))
        self.assertEqual(r.action, "replied")
        self.assertEqual(r.detail, "help")

    def test_mention_wrong_bot_is_ignored(self):
        bot, gh, tg = make_bot()
        r = bot.handle_update(group_update(
            3, USER_ID, GROUP_ID, "/help@SomeOtherBot"))
        self.assertEqual(r.action, "ignored")
        self.assertEqual(tg.sent, [])

    def test_reply_to_bot_in_group_is_served(self):
        bot, gh, tg = make_bot()
        r = bot.handle_update(group_update(
            3, USER_ID, GROUP_ID, "/help", reply_to_bot=True))
        self.assertEqual(r.action, "replied")
        self.assertEqual(r.detail, "help")

    def test_reply_to_someone_else_is_ignored(self):
        bot, gh, tg = make_bot()
        r = bot.handle_update(group_update(
            3, USER_ID, GROUP_ID, "/help", reply_to_bot=True,
            reply_from_id=424242))
        self.assertEqual(r.action, "ignored")
        self.assertEqual(tg.sent, [])

    def test_group_audit_mention_runs(self):
        bot, gh, tg = make_bot()
        r = bot.handle_update(group_update(
            4, USER_ID, GROUP_ID, f"/audit@{BOT_USERNAME} https://github.com/o/r"))
        self.assertTrue(r.detail.startswith("audit:o/r"))
        self.assertEqual(len(gh.calls), 2)


class TestThreadPreservation(unittest.TestCase):
    def test_reply_preserves_message_thread_id(self):
        bot, _, tg = make_bot()
        bot.handle_update(dm_update(1, USER_ID, "/help", thread_id=777))
        self.assertEqual(tg.sent[0].get("message_thread_id"), 777)

    def test_group_reply_preserves_thread_id(self):
        bot, _, tg = make_bot()
        bot.handle_update(group_update(
            1, USER_ID, GROUP_ID, f"/help@{BOT_USERNAME}", thread_id=888))
        self.assertEqual(tg.sent[0].get("message_thread_id"), 888)


class TestStartupGuard(unittest.TestCase):
    def test_verify_startup_ok(self):
        bot, _, tg = make_bot()
        identity = bot.verify_startup()
        self.assertEqual(identity["id"], BOT_ID)
        self.assertEqual(identity["username"], BOT_USERNAME)

    def test_wrong_identity_fails_closed(self):
        tg = FakeTelegram(bot_id=111111)
        bot, _, _ = make_bot(tg=tg)
        with self.assertRaises(TelegramError):
            bot.verify_startup()

    def test_webhook_configured_fails_closed(self):
        tg = FakeTelegram(webhook_url="https://example.com/hook")
        bot, _, _ = make_bot(tg=tg)
        with self.assertRaises(TelegramError):
            bot.verify_startup()


class TestBotHygiene(unittest.TestCase):
    def test_token_never_sent_as_message_text(self):
        bot, _, tg = make_bot()
        bot.handle_update(dm_update(1, USER_ID, "/start"))
        bot.handle_update(dm_update(2, USER_ID, "/audit https://github.com/a/b"))
        for sent in tg.sent:
            self.assertNotIn(FAKE_TOKEN, sent.get("text", ""))

    def test_poll_once_advances_offset_and_dispatches(self):
        tg = FakeTelegram(updates=[dm_update(10, USER_ID, "/start"),
                                   dm_update(11, 999999, "/help")])
        bot, _, tg = make_bot(tg=tg)
        new_offset, results = bot.poll_once(0)
        self.assertEqual(new_offset, 12)
        self.assertEqual([r.detail for r in results], ["start", "sender not allowlisted"])

    def test_auth_error_stops_run(self):
        class BadTG(FakeTelegram):
            def __call__(self, url, method, body, timeout):
                from tests.devin_fixtures import make_response
                return make_response(401, b'{"ok":false,"description":"Unauthorized"}')
        bot, _, _ = make_bot(tg=BadTG())
        with self.assertRaises(TelegramError):
            bot._call("getUpdates", {"offset": 0})
        self.assertTrue(bot._is_auth_error(TelegramError("getUpdates failed: Unauthorized")))


if __name__ == "__main__":
    unittest.main()