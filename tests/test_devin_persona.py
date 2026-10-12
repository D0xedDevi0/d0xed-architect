"""Persona copy — Telegram limits + voice invariants (Looper #706)."""
import unittest

from devin.report import (ABOUT, COMMANDS, DESCRIPTION, HELP_TEXT, PHOTO,
                          START_TEXT, render_lore)

DESC_MAX = 512        # telegram setMyDescription
ABOUT_MAX = 120       # telegram setMyShortDescription
MSG_MAX = 4096        # telegram sendMessage


class TestPersonaCopy(unittest.TestCase):
    def test_description_within_telegram_limit(self):
        self.assertGreater(len(DESCRIPTION), 200)
        self.assertLessEqual(len(DESCRIPTION), DESC_MAX)

    def test_about_within_telegram_limit(self):
        self.assertLessEqual(len(ABOUT), ABOUT_MAX)

    def test_welcome_and_help_bounded(self):
        for text in (START_TEXT, HELP_TEXT):
            self.assertTrue(text.strip())
            self.assertLessEqual(len(text), MSG_MAX)

    def test_command_menu_shape(self):
        names = [c["command"] for c in COMMANDS]
        self.assertEqual(names,
                         ["start", "help", "lore", "audit", "debug", "map", "doctor"])
        for c in COMMANDS:
            self.assertRegex(c["command"], r"^[a-z0-9_]{1,32}$")
            self.assertTrue(1 <= len(c["description"]) <= 256)

    def test_identity_present(self):
        for text in (DESCRIPTION, START_TEXT, HELP_TEXT):
            self.assertIn("706", text)

    def test_voice_core_present(self):
        for text in (DESCRIPTION, START_TEXT):
            self.assertIn("Reads state, not vibes", text)

    def test_guarantees_stated_and_not_contradicted(self):
        low = DESCRIPTION.lower()
        self.assertIn("static only", low)
        self.assertIn("never run your code", low)
        self.assertIn("never touch a wallet", low)
        self.assertIn("never executed", HELP_TEXT.lower())

    def test_square_bullet_brand_marker(self):
        self.assertIn("🟦", DESCRIPTION)
        self.assertIn("🟦", START_TEXT)


class TestLore(unittest.TestCase):
    def test_lore_carries_onchain_identity(self):
        text = render_lore()
        for needle in ("Looper #706", "87226", "Builder / Engineer",
                       "Mercenary / Fixer", "MCP Router Side Logs",
                       "came up inside mcp router side logs", "Wire a tool"):
            self.assertIn(needle, text, needle)

    def test_lore_bounded(self):
        self.assertLessEqual(len(render_lore()), MSG_MAX)

    def test_photo_points_at_the_looper_art(self):
        self.assertTrue(PHOTO.startswith("https://"))
        self.assertIn("arweave.net", PHOTO)


if __name__ == "__main__":
    unittest.main()
