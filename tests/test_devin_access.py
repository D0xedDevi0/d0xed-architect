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

    def test_other_member_of_allowlisted_group_is_authorized(self):
        # The ROOM is the principal: any member may use the bot once they
        # address it. Gating a room on the owner's user id made a group the
        # bot had been added to look completely dead to everyone else.
        d = self.auth.decide(group_update(8, 424242, GROUP_ID, "/help"))
        self.assertTrue(d.ok)
        self.assertEqual(d.reason, "group")

    def test_bot_sender_in_allowlisted_group_reaches_the_bot_layer(self):
        upd = group_update(9, 777000, GROUP_ID, "/help")
        upd["message"]["from"]["is_bot"] = True
        d = self.auth.decide(upd)
        self.assertTrue(d.ok)
        # Allowed here, but the bot layer still holds it to an addressed
        # /command@self so sibling bots cannot start a conversation.
        self.assertEqual(d.reason, "group-bot")

    def test_no_groups_configured_denies_group(self):
        auth = Authorizer([USER_ID], [])
        d = auth.decide(group_update(5, USER_ID, GROUP_ID, "/help"))
        self.assertFalse(d.ok)

    def test_open_dms_accept_a_stranger_in_private(self):
        # `*` in DEVIN_ALLOWED_USERS — the owner's choice to serve the public
        # from his DMs. Nobody is named, and a stranger is served.
        auth = Authorizer([], [GROUP_ID], open_dms=True)
        d = auth.decide(dm_update(10, 424242, "/help"))
        self.assertTrue(d.ok)
        self.assertEqual(d.reason, "dm-open")

    def test_open_dms_never_open_a_room(self):
        # The open token lives in the USER allowlist, and the group branch never
        # consults it, so it cannot expose a group DEVin was not added to.
        auth = Authorizer([], [GROUP_ID], open_dms=True)
        d = auth.decide(group_update(11, 424242, -123, "/help"))
        self.assertFalse(d.ok)
        self.assertEqual(d.reason, "group not allowlisted")

    def test_open_dms_do_not_disturb_the_named_path(self):
        auth = Authorizer([USER_ID], [GROUP_ID], open_dms=True)
        self.assertTrue(auth.decide(dm_update(12, USER_ID, "/help")).ok)
        self.assertEqual(auth.decide(group_update(13, USER_ID, GROUP_ID,
                                                 "/help")).reason, "group")

    def test_dms_stay_closed_without_the_token(self):
        d = self.auth.decide(dm_update(14, 424242, "/help"))
        self.assertFalse(d.ok)
        self.assertEqual(d.reason, "sender not allowlisted")

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
