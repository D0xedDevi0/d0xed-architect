"""Access control: allowlisted users + optional groups, deny everything else."""
import unittest

from devin.access import Authorizer
from tests.devin_fixtures import GROUP_ID, USER_ID, dm_update, group_update


class TestAccess(unittest.TestCase):
    def setUp(self):
        self.auth = Authorizer([USER_ID], [GROUP_ID])

    def test_allowed_dm(self):
        d = self.auth.decide(dm_update(1, USER_ID, "/help"))
        self.assertTrue(d.ok)
        self.assertEqual(d.reason, "dm")

    def test_allowed_group(self):
        d = self.auth.decide(group_update(2, USER_ID, GROUP_ID, "/help"))
        self.assertTrue(d.ok)
        self.assertEqual(d.reason, "group")

    def test_wrong_group_denied(self):
        d = self.auth.decide(group_update(3, USER_ID, -123, "/help"))
        self.assertFalse(d.ok)
        self.assertEqual(d.reason, "group not allowlisted")

    def test_other_user_denied(self):
        d = self.auth.decide(dm_update(4, 999999, "/help"))
        self.assertFalse(d.ok)
        self.assertEqual(d.reason, "sender not allowlisted")

    def test_no_groups_configured_denies_group(self):
        auth = Authorizer([USER_ID], [])
        d = auth.decide(group_update(5, USER_ID, GROUP_ID, "/help"))
        self.assertFalse(d.ok)

    def test_channel_denied(self):
        upd = {"update_id": 6,
               "message": {"message_id": 1, "from": {"id": USER_ID},
                           "chat": {"id": -100, "type": "channel"}, "text": "/help"}}
        d = self.auth.decide(upd)
        self.assertFalse(d.ok)
        self.assertIn("chat type not allowed", d.reason)

    def test_edited_message_ignored(self):
        upd = {"update_id": 7,
               "edited_message": {"message_id": 1, "from": {"id": USER_ID},
                                  "chat": {"id": USER_ID, "type": "private"},
                                  "text": "/help"}}
        self.assertFalse(self.auth.decide(upd).ok)

    def test_malformed_update_denied(self):
        self.assertFalse(self.auth.decide(None).ok)
        self.assertFalse(self.auth.decide("nope").ok)


if __name__ == "__main__":
    unittest.main()
