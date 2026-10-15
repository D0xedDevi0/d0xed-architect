"""Paid Jev lane: synthetic tests, no network and no production state."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from devin.commands import parse_command
from devin.config import Config, Limits
from devin.bot import DevinBot
from devin.jev import JevLane, JevBudget, resolve_jev_key
from devin_fixtures import FakeTelegram, FakeGithub, USER_ID, GROUP_ID, BOT_ID, BOT_USERNAME, FAKE_TOKEN, dm_update

class DevinJevTests(unittest.TestCase):
    def test_command_registration_and_strict_syntax(self):
        c=parse_command('/judge@DEVinlooperbot https://example.org/ | SDK integration',500)
        self.assertEqual(c.kind,'judge')
        for text in ['/judge','/judge https://example.org/','/judge https://u:p@example.org/ | docs','/judge https://example.org/?token=secret | docs']:
            self.assertEqual(parse_command(text,500).kind,'reject')

    def test_only_named_humans_can_reach_paid_lane(self):
        calls=[]
        config=Config(FAKE_TOKEN,(USER_ID,),(GROUP_ID,),Limits(),BOT_ID,BOT_USERNAME,open_dms=True)
        tg=FakeTelegram();bot=DevinBot(config,tg,FakeGithub(),judge=lambda url,objective,request_id:calls.append((url,objective,request_id)) or 'Jev observed public documentation.')
        # Real dispatcher, not a direct helper-only test.
        for actor,is_bot in [(123456,False),(USER_ID,True)]:
            u=dm_update(1,actor,'/judge https://example.org/ | SDK docs')
            u['message']['from']['is_bot']=is_bot
            bot.handle_update(u)
        self.assertEqual(calls,[])
        u=dm_update(2,USER_ID,'/judge https://example.org/ | SDK docs')
        bot.handle_update(u)
        self.assertEqual(len(calls),1)
        self.assertEqual(calls[0][:2],('https://example.org/','SDK docs'))
        sent=tg.sent[-1]
        self.assertIn('reply_to_message_id',sent)

    def test_daily_budget_persists_dedup_and_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/'jev';a=JevBudget(root,daily_limit=2,min_gap=0)
            self.assertTrue(a.reserve('request-a',now=1800000000))
            self.assertFalse(JevBudget(root,daily_limit=2,min_gap=0).reserve('request-a',now=1800000001))
            self.assertTrue(a.reserve('request-b',now=1800000002))
            self.assertFalse(a.reserve('request-c',now=1800000003))
            (root/'budget.json').write_text('{}')
            with self.assertRaises(ValueError):a.reserve('request-d',now=1800000004)
            self.assertEqual((root/'budget.json').read_text(),'{}')

    def test_budget_rejects_symlinks_and_unsafe_options(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/'jev';a=JevBudget(root)
            target=Path(tmp)/'target';target.write_text('keep')
            (root/'budget.json').symlink_to(target)
            with self.assertRaises((ValueError,OSError)):a.reserve('a')
            self.assertEqual(target.read_text(),'keep')
        for cap in [0,51,True]:
            with self.assertRaises(ValueError):JevBudget(Path('/nonexistent-should-not-create'),daily_limit=cap)

    def test_encrypted_credential_first_and_no_repr_leak(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp,'typesafe_api_key').write_text('TEST_ONLY_KEY')
            self.assertEqual(resolve_jev_key({'CREDENTIALS_DIRECTORY':tmp,'TYPESAFE_API_KEY':'OTHER_TEST'}),'TEST_ONLY_KEY')
        self.assertNotIn('TEST_ONLY_KEY',repr(JevLane('TEST_ONLY_KEY',None)))
