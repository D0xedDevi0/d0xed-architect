"""Command parsing: bounded; /start /help /doctor (no arg), /audit /debug /map
(one URL arg)."""
import unittest

from devin.commands import COMMANDS, parse_command

URL = "https://github.com/owner/repo"


class TestCommands(unittest.TestCase):
    def test_start(self):
        c = parse_command("/start", 500)
        self.assertEqual(c.kind, "start")

    def test_help(self):
        self.assertEqual(parse_command("/help", 500).kind, "help")

    def test_doctor_no_arg(self):
        c = parse_command("/doctor", 500)
        self.assertEqual(c.kind, "doctor")
        self.assertIsNone(c.arg)

    def test_audit(self):
        c = parse_command(f"/audit {URL}", 500)
        self.assertEqual(c.kind, "audit")
        self.assertEqual(c.arg, URL)

    def test_debug(self):
        c = parse_command(f"/debug {URL}", 500)
        self.assertEqual(c.kind, "debug")
        self.assertEqual(c.arg, URL)

    def test_map(self):
        c = parse_command("/map https://example.com", 500)
        self.assertEqual(c.kind, "map")
        self.assertEqual(c.arg, "https://example.com")

    def test_audit_strips_bot_mention(self):
        c = parse_command(f"/audit@DevBot {URL}", 500)
        self.assertEqual(c.kind, "audit")
        self.assertEqual(c.arg, URL)

    def test_audit_no_arg_rejected(self):
        c = parse_command("/audit", 500)
        self.assertEqual(c.kind, "reject")
        self.assertIn("usage", c.error)

    def test_debug_no_arg_rejected(self):
        c = parse_command("/debug", 500)
        self.assertEqual(c.kind, "reject")
        self.assertIn("usage", c.error)

    def test_map_no_arg_rejected(self):
        c = parse_command("/map", 500)
        self.assertEqual(c.kind, "reject")

    def test_audit_two_args_rejected(self):
        c = parse_command(f"/audit {URL} extra", 500)
        self.assertEqual(c.kind, "reject")

    def test_unknown_command_rejected(self):
        self.assertEqual(parse_command("/foo", 500).kind, "reject")

    def test_plain_text_rejected(self):
        self.assertEqual(parse_command("hello", 500).kind, "reject")

    def test_empty_rejected(self):
        self.assertEqual(parse_command(None, 500).kind, "reject")
        self.assertEqual(parse_command("", 500).kind, "reject")

    def test_oversized_rejected(self):
        self.assertEqual(parse_command("/start" + " " * 600, 500).kind, "reject")

    def test_command_table(self):
        self.assertEqual(COMMANDS,
                         ("/start", "/help", "/spellbook", "/lore", "/audit",
                          "/debug", "/map", "/crawl", "/sitemap", "/link",
                          "/bundle", "/sigil", "/doctor", "/judge"))


if __name__ == "__main__":
    unittest.main()
