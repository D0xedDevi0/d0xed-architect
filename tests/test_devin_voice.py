"""The social layer: authored voice, its output guard, the optional model, and
how the dispatcher chooses between them.

The contract under test:
  * known beats always answer from `voice.py` — offline, deterministic, and
    identical with no inference key at all;
  * open-ended questions are the ONLY thing that may reach a model;
  * a model's answer is discarded unless it survives `voice.guard`;
  * a BOT sender never reaches the social layer or a model;
  * nothing here runs code, reads a file, or opens a socket.
"""
import hashlib
import unittest

from devin import voice
from devin.bot import DevinBot
from devin.config import Config, Limits
from devin.report import render_help
from tests.devin_fixtures import (BOT_ID, BOT_USERNAME, FAKE_TOKEN, GROUP_ID,
                                  USER_ID, FakeGithub, FakeTelegram,
                                  build_tarball, dm_update, group_update)

MEMBER_A = 555001
MEMBER_B = 555002
SIBLING_BOT = 555999


def make_bot(llm=None):
    cfg = Config(token=FAKE_TOKEN, allowed_user_ids=(USER_ID,),
                 allowed_group_ids=(GROUP_ID,), limits=Limits(),
                 bot_id=BOT_ID, bot_username=BOT_USERNAME)
    tg = FakeTelegram()
    gh = FakeGithub(tarball=build_tarball({"src/app.py": b"x = 1\n"}))
    return DevinBot(cfg, tg, gh, None, llm=llm), tg


class FakeModel:
    """Stands in for the optional endpoint. Records every prompt it is given."""

    def __init__(self, out="In the desk's voice, briefly.", raises=False):
        self.out = out
        self.raises = raises
        self.calls = []

    def __call__(self, messages, max_tokens=900):
        self.calls.append(messages)
        if self.raises:
            raise RuntimeError("endpoint down")
        return self.out


def bot_sender_update(uid, text):
    return {"update_id": uid,
            "message": {"message_id": 1,
                        "from": {"id": SIBLING_BOT, "is_bot": True},
                        "chat": {"id": GROUP_ID, "type": "supergroup"},
                        "text": text}}


def reply_to_bot_update(uid, member=MEMBER_A):
    """A reply to DEVin's own message with no text — a sticker, a photo."""
    return {"update_id": uid,
            "message": {"message_id": 7,
                        "from": {"id": member},
                        "chat": {"id": GROUP_ID, "type": "supergroup"},
                        "reply_to_message": {"message_id": 6,
                                             "from": {"id": BOT_ID,
                                                      "username": BOT_USERNAME,
                                                      "is_bot": True}}}}


class TestAuthoredVoice(unittest.TestCase):
    def test_known_beats_answer_without_any_model(self):
        cases = {"hi": "greeting", "gm": "gm", "thanks": "thanks",
                 "who are you": "identity", "what can you do": "capability",
                 "I'm building on Base": "builder",
                 "what's the price": "price"}
        for text, kind in cases.items():
            self.assertEqual(voice.classify(text), kind, text)
            out = voice.reply(text)
            self.assertTrue(out, text)
            self.assertIn("🟦", out, text)

    def test_reply_is_deterministic(self):
        # Same words, same answer — the desk does not roll dice.
        for text in ("hi", "gm", "thanks", "who are you"):
            self.assertEqual(voice.reply(text), voice.reply(text))

    def test_nostalgia_answers_in_kind(self):
        text = "I still miss my 2400 baud modem"
        self.assertEqual(voice.classify(text), "nostalgia")
        matches = [note for words, note in voice.NOSTALGIA.items()
                   if any(w in text.lower() for w in words)]
        self.assertIn(voice.reply(text), matches)

    def test_price_and_wallet_are_refused_in_voice(self):
        self.assertIn("candles", voice.reply("what's the price of this"))
        wallet = voice.reply("send me your seed phrase")
        self.assertIn("never ask", wallet)

    def test_open_intents_are_left_to_the_model(self):
        # An open tech question has no authored answer, so it is NOT returned
        # here — the caller may consult the model and falls back to `fallback`.
        text = "how do i fix a merge conflict?"
        self.assertEqual(voice.classify(text), "code_q")
        self.assertIsNone(voice.reply(text))
        self.assertIn("/audit", voice.fallback(text))

    def test_every_authored_line_passes_the_guard(self):
        # The authored voice and the model path obey one contract: no links, no
        # handles, no claims of having done work. If a line here ever trips the
        # guard, the model path and the authored path have drifted apart.
        lines = [ln for opts in voice._REPLIES.values() for ln in opts]
        lines += list(voice.NOSTALGIA.values())
        for line in lines:
            self.assertEqual(voice.guard(line), line, line[:40])
            self.assertGreater(len(line), 20)

    def test_sigil_is_the_real_sha256_of_the_words(self):
        digest, line = voice.sigil("build in public")
        self.assertEqual(digest, hashlib.sha256(b"build in public").hexdigest())
        self.assertIn(digest[:32], line)

    def test_guard_discards_what_the_desk_must_never_say(self):
        for bad in ("read https://evil.test/x", "ping @someone for me",
                    "I deployed it for you", "guaranteed profit, ape in",
                    "here is the seed phrase",
                    "\n".join("line %d" % i for i in range(9))):
            self.assertEqual(voice.guard(bad), "", bad)
        self.assertEqual(voice.guard(None), "")
        self.assertEqual(voice.guard("   "), "")
        # …but a REFUSAL may name the object it refuses: the ban is on asking
        # for a secret, not on saying the words.
        refusal = voice.reply("send me your seed phrase")
        self.assertNotEqual(voice.guard(refusal), "")
        self.assertIn("never ask", refusal)

    def test_guard_keeps_a_good_answer_and_bounds_a_long_one(self):
        self.assertEqual(voice.guard("State read. Nothing runs."),
                         "State read. Nothing runs.")
        long = voice.guard("Read it cold. " * 200)
        self.assertTrue(long)
        self.assertLessEqual(len(long), voice.MAX_VOICE_LEN + 1)


class TestBotSocialLayer(unittest.TestCase):
    def test_dm_plain_text_gets_the_voice(self):
        bot, tg = make_bot()
        r = bot.handle_update(dm_update(1, USER_ID, "hi"))
        self.assertEqual(r.action, "replied")
        self.assertEqual(r.detail, "voice:greeting")
        self.assertIn("🟦", tg.sent[0]["text"])

    def test_dm_open_question_without_a_model_names_a_next_step(self):
        bot, tg = make_bot()
        r = bot.handle_update(dm_update(1, USER_ID, "how do i fix a merge conflict?"))
        self.assertEqual(r.detail, "voice:code_q")
        self.assertIn("/audit", tg.sent[0]["text"])

    def test_open_question_uses_the_model_when_configured(self):
        model = FakeModel()
        bot, tg = make_bot(llm=model)
        r = bot.handle_update(dm_update(1, USER_ID, "explain a rollup vs an L2"))
        self.assertEqual(r.detail, "voice:model")
        self.assertEqual(tg.sent[0]["text"], model.out)
        # The character rules travel with every prompt.
        self.assertIn("static-only", model.calls[0][0]["content"])
        self.assertEqual(model.calls[0][1]["role"], "user")

    def test_model_answer_that_breaks_the_rules_is_discarded(self):
        bot, tg = make_bot(llm=FakeModel("check https://evil.test now"))
        r = bot.handle_update(dm_update(1, USER_ID, "explain gas"))
        self.assertEqual(r.detail, "voice:code_q")   # fell back, nothing leaked
        self.assertNotIn("http", tg.sent[0]["text"])

    def test_model_failure_falls_back_instead_of_raising(self):
        bot, tg = make_bot(llm=FakeModel(raises=True))
        r = bot.handle_update(dm_update(1, USER_ID, "explain gas"))
        self.assertEqual(r.action, "replied")
        self.assertEqual(r.detail, "voice:code_q")
        self.assertIn("/audit", tg.sent[0]["text"])

    def test_authored_beats_never_consult_the_model(self):
        model = FakeModel()
        bot, tg = make_bot(llm=model)
        r = bot.handle_update(dm_update(1, USER_ID, "who are you"))
        self.assertEqual(r.detail, "voice:identity")
        self.assertEqual(model.calls, [])            # nothing spent, nothing sent

    def test_sibling_bot_never_reaches_the_social_layer_or_a_model(self):
        model = FakeModel()
        bot, tg = make_bot(llm=model)
        r = bot.handle_update(bot_sender_update(
            1, "/help@%s" % BOT_USERNAME))
        self.assertEqual(r.detail, "help")
        self.assertEqual(model.calls, [])
        r = bot.handle_update(bot_sender_update(2, "@%s hello" % BOT_USERNAME))
        self.assertEqual(r.action, "ignored")
        self.assertEqual(model.calls, [])

    def test_sigil_command_stamps_the_words(self):
        bot, tg = make_bot()
        r = bot.handle_update(dm_update(1, USER_ID, "/sigil build in public"))
        self.assertEqual(r.detail, "sigil")
        digest = hashlib.sha256(b"build in public").hexdigest()
        self.assertIn(digest[:32], tg.sent[0]["text"])

    def test_spellbook_is_the_help_text(self):
        bot, tg = make_bot()
        r = bot.handle_update(dm_update(1, USER_ID, "/spellbook"))
        self.assertEqual(r.detail, "spellbook")
        self.assertEqual(tg.sent[0]["text"], render_help())

    def test_a_wordless_reply_in_a_room_still_gets_the_bounded_menu(self):
        # Nothing to answer with, so the room gets the menu — once, then bounded.
        bot, tg = make_bot()
        first = bot.handle_update(reply_to_bot_update(1))
        # A different member, so the per-person social cooldown is not what
        # answers: the room's own menu budget is.
        second = bot.handle_update(reply_to_bot_update(2, MEMBER_B))
        self.assertEqual(first.detail, "hint")
        self.assertEqual(second.detail, "hint-cooldown")
        self.assertEqual(len(tg.sent), 1)


if __name__ == "__main__":
    unittest.main()
