"""Bounded self-diagnostics: never prints either token value."""
import unittest

from devin.config import Config, Limits
from devin.doctor import render_doctor
from tests.devin_fixtures import (BOT_ID, BOT_USERNAME, FAKE_GITHUB_TOKEN,
                                  FAKE_TOKEN, GROUP_ID, USER_ID)


def cfg(**kw):
    base = dict(token=FAKE_TOKEN, allowed_user_ids=(USER_ID,),
                allowed_group_ids=(GROUP_ID,), limits=Limits(),
                bot_id=BOT_ID, bot_username=BOT_USERNAME)
    base.update(kw)
    return Config(**base)


class TestDoctor(unittest.TestCase):
    def test_reports_identity_counts_and_limits(self):
        text = render_doctor(cfg(), bot_id=BOT_ID, bot_username=BOT_USERNAME)
        self.assertIn(str(BOT_ID), text)
        self.assertIn(BOT_USERNAME, text)
        self.assertIn("users=1", text)
        self.assertIn("groups=1", text)
        self.assertIn("webhook: clear", text)
        self.assertIn("github token configured: no", text)

    def test_webhook_set_reported(self):
        text = render_doctor(cfg(), webhook_url="https://x/hook")
        self.assertIn("webhook: set", text)

    def test_github_token_boolean_only(self):
        text = render_doctor(cfg(github_token=FAKE_GITHUB_TOKEN))
        self.assertIn("github token configured: yes", text)
        self.assertNotIn(FAKE_GITHUB_TOKEN, text)

    def test_never_leaks_bot_token(self):
        text = render_doctor(cfg(github_token=FAKE_GITHUB_TOKEN))
        self.assertNotIn(FAKE_TOKEN, text)

    def test_counts_not_ids(self):
        text = render_doctor(cfg())
        self.assertNotIn(str(USER_ID), text)
        self.assertNotIn(str(GROUP_ID), text)

    def test_truncated_to_max_len(self):
        text = render_doctor(cfg(), max_len=40)
        self.assertLessEqual(len(text), 40)
        self.assertIn("truncated", text)


if __name__ == "__main__":
    unittest.main()
