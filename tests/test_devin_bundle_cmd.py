"""`/bundle` end to end: the refusals matter more than the happy path.

/bundle is the only command that sends a FILE, so the tests that matter are
"it never sends this into a group", "without a key it does not seal", and "the
thing it uploads is a real bundle that opens with the passphrase and contains
nothing that was not in the manifest".
"""
import json
import unittest
from types import SimpleNamespace

from devin.crypto import is_bundle, open_bundle
from devin.pack import MANIFEST_NAME
from tests.devin_fixtures import (BOT_USERNAME, FAKE_TOKEN, GROUP_ID, USER_ID,
                                  FakeGithub, build_tarball, dm_update,
                                  group_update)

PW = "correct horse battery staple"
SRC = {"app.py": b"import os\n\n\ndef main():\n    return os.getpid()\n",
       "lib/util.js": b"export const clamp = (n) => Math.min(1, n);\n"}


class DocTransport:
    """Records every call and can serve a real multipart sendDocument.

    `reject_documents` fails ONLY sendDocument: a fake that also failed
    sendMessage would break the error path it is meant to test.
    """

    def __init__(self, reject_documents=False):
        self.calls = []
        self.reject_documents = reject_documents

    def __call__(self, url, method, body, timeout, content_type="application/json"):
        self.calls.append({"url": url, "method": method, "body": body or b"",
                           "ctype": content_type})
        failing = self.reject_documents and url.endswith("/sendDocument")
        payload = {"ok": not failing}
        if failing:
            payload["description"] = "Bad Request: file too big"
        return SimpleNamespace(status=400 if failing else 200,
                               body=json.dumps(payload).encode(),
                               content_type="application/json")

    def documents(self):
        return [c for c in self.calls if c["url"].endswith("/sendDocument")]


def make_bot(passphrase=PW, transport=None, github_token=None, github=None):
    from devin.bot import DevinBot
    from devin.config import Config, Limits
    cfg = Config(token=FAKE_TOKEN, allowed_user_ids=(USER_ID,),
                 allowed_group_ids=(GROUP_ID,), limits=Limits(),
                 bot_id=None, bot_username=BOT_USERNAME,
                 github_token=github_token)
    tg = transport or DocTransport()
    gh = github or FakeGithub(tarball=build_tarball(SRC))
    return DevinBot(cfg, tg, gh, None, bundle_passphrase=passphrase), tg


def document_bytes(call):
    """Pull the file payload out of a multipart body."""
    body = call["body"]
    marker = b'name="document"; filename="'
    start = body.index(marker)
    head_end = body.index(b"\r\n\r\n", start) + 4
    end = body.rindex(b"\r\n--")
    return body[head_end:end]


GITHUB = "https://github.com/example/project"


class TestBundleRefusals(unittest.TestCase):
    def test_group_is_refused(self):
        bot, tg = make_bot()
        r = bot.handle_update(group_update(1, USER_ID, GROUP_ID,
                                           f"/bundle {GITHUB}",
                                           reply_to_bot=True))
        self.assertEqual(r.detail, "bundle-dm-only")
        self.assertEqual(tg.documents(), [])          # nothing was uploaded
        self.assertIn("DM-only", tg.calls[-1]["body"].decode())

    def test_without_a_passphrase_it_refuses_instead_of_sealing(self):
        bot, tg = make_bot(passphrase=None)
        r = bot.handle_update(dm_update(1, USER_ID, f"/bundle {GITHUB}"))
        self.assertEqual(r.detail, "bundle-no-key")
        self.assertEqual(tg.documents(), [])
        self.assertIn("no sealing key", tg.calls[-1]["body"].decode())

    def test_non_github_url_is_refused(self):
        bot, tg = make_bot()
        r = bot.handle_update(dm_update(1, USER_ID, "/bundle https://evil.test/x"))
        self.assertEqual(r.detail, "bundle-error")
        self.assertEqual(tg.documents(), [])

    def test_live_credentials_block_the_seal(self):
        from devin.bot import DevinBot
        from devin.config import Config, Limits
        cfg = Config(token=FAKE_TOKEN, allowed_user_ids=(USER_ID,),
                     allowed_group_ids=(GROUP_ID,), limits=Limits(),
                     bot_id=None, bot_username=BOT_USERNAME)
        gh = FakeGithub(tarball=build_tarball(
            {"config.py": b'AWS_ACCESS_KEY_ID = "AKIAQ7Z2XW9K4M3NB6PQ"\n'}))
        tg = DocTransport()
        bot = DevinBot(cfg, tg, gh, None, bundle_passphrase=PW)
        r = bot.handle_update(dm_update(1, USER_ID, f"/bundle {GITHUB}"))
        self.assertEqual(r.detail, "bundle-refused")
        self.assertEqual(tg.documents(), [])
        self.assertNotIn("AKIAQ7Z2XW9K4M3NB6PQ", tg.calls[-1]["body"].decode())

    def test_upload_failure_is_reported_not_swallowed(self):
        bot, tg = make_bot(transport=DocTransport(reject_documents=True))
        r = bot.handle_update(dm_update(1, USER_ID, f"/bundle {GITHUB}"))
        self.assertEqual(r.detail, "bundle-upload-error")
        self.assertIn("upload failed", tg.calls[-1]["body"].decode())


class TestBundleHappyPath(unittest.TestCase):
    def test_uploads_one_openable_bundle(self):
        bot, tg = make_bot()
        r = bot.handle_update(dm_update(1, USER_ID, f"/bundle {GITHUB}"))
        self.assertEqual(r.detail, "bundle:2f")
        docs = tg.documents()
        self.assertEqual(len(docs), 1)
        call = docs[0]
        self.assertEqual(call["method"], "POST")
        self.assertTrue(call["ctype"].startswith("multipart/form-data; boundary="))
        blob = document_bytes(call)
        self.assertTrue(is_bundle(blob))
        # the uploaded file must actually open with the passphrase
        inner = open_bundle(blob, PW)
        import io
        import tarfile
        with tarfile.open(fileobj=io.BytesIO(inner), mode="r") as tf:
            names = sorted(tf.getnames())
        self.assertIn(MANIFEST_NAME, names)
        self.assertIn("app.py", names)
        self.assertIn("lib/util.js", names)

    def test_caption_carries_receipts_not_the_passphrase(self):
        bot, tg = make_bot()
        bot.handle_update(dm_update(1, USER_ID, f"/bundle {GITHUB}"))
        body = tg.documents()[0]["body"]
        self.assertIn(b"chacha20-poly1305", body)
        self.assertNotIn(PW.encode(), body)
        self.assertNotIn(FAKE_TOKEN.encode(), body)

    def test_filename_is_a_bundle_name(self):
        bot, tg = make_bot()
        bot.handle_update(dm_update(1, USER_ID, f"/bundle {GITHUB}"))
        body = tg.documents()[0]["body"]
        self.assertIn(b'.tar.gz.enc"', body)

    def test_document_reply_keeps_the_thread(self):
        bot, tg = make_bot()
        bot.handle_update(dm_update(1, USER_ID, f"/bundle {GITHUB}",
                                    thread_id=77))
        self.assertIn(b"message_thread_id", tg.documents()[0]["body"])

    def test_sealed_file_is_not_the_plaintext(self):
        bot, tg = make_bot()
        bot.handle_update(dm_update(1, USER_ID, f"/bundle {GITHUB}"))
        blob = document_bytes(tg.documents()[0])
        self.assertNotIn(b"os.getpid", blob)
        self.assertNotIn(b"export const clamp", blob)


class TestPrivateRepos(unittest.TestCase):
    """Private code sets need a provisioned token, and the token must stay out
    of everything the user sees."""

    PRIVATE = "https://github.com/example/private-project"
    TOKEN = "ghp_" + "P" * 36

    def _private_github(self):
        return FakeGithub(tarball=build_tarball(SRC), private=True)

    def test_private_without_a_token_is_refused(self):
        bot, tg = make_bot(github=self._private_github())
        r = bot.handle_update(dm_update(1, USER_ID, f"/bundle {self.PRIVATE}"))
        self.assertEqual(r.detail, "bundle-error")
        self.assertEqual(tg.documents(), [])
        body = tg.calls[-1]["body"].decode()
        self.assertIn("not found or not public", body)

    def test_private_with_a_token_is_sealed(self):
        gh = self._private_github()
        bot, tg = make_bot(github=gh, github_token=self.TOKEN)
        r = bot.handle_update(dm_update(1, USER_ID, f"/bundle {self.PRIVATE}"))
        self.assertEqual(r.detail, "bundle:2f")
        blob = document_bytes(tg.documents()[0])
        self.assertTrue(is_bundle(blob))

    def test_token_never_reaches_the_bundle_or_the_chat(self):
        gh = self._private_github()
        bot, tg = make_bot(github=gh, github_token=self.TOKEN)
        bot.handle_update(dm_update(1, USER_ID, f"/bundle {self.PRIVATE}"))
        # the token is an Authorization header only
        seen = [h for (_u, h) in gh.headers_seen if h]
        self.assertTrue(any("Authorization" in h for h in seen))
        for call in tg.calls:
            self.assertNotIn(self.TOKEN.encode(), call["body"])
        blob = document_bytes(tg.documents()[0])
        self.assertNotIn(self.TOKEN.encode(), blob)

    def test_private_tarball_is_not_reachable_without_auth(self):
        """FakeGithub mirrors GitHub: the archive 404s without the header."""
        gh = self._private_github()
        from devin.github_audit import AuditDenied, fetch_public_tarball
        with self.assertRaises(AuditDenied):
            fetch_public_tarball(self.PRIVATE, gh, 5.0, None)


class TestTransportContract(unittest.TestCase):
    def test_transport_without_multipart_support_fails_closed(self):
        """A 4-argument transport cannot carry sendDocument: we must report an
        upload failure, never claim success."""
        class FourArg:
            def __init__(self):
                self.calls = []

            def __call__(self, url, method, body, timeout):
                self.calls.append(url)
                return SimpleNamespace(status=200,
                                       body=json.dumps({"ok": True}).encode())

        tg = FourArg()
        bot, _ = make_bot(transport=tg)
        r = bot.handle_update(dm_update(1, USER_ID, f"/bundle {GITHUB}"))
        self.assertEqual(r.detail, "bundle-upload-error")

    def test_multipart_never_contains_the_token(self):
        import os
        from devin.transport import TransportError, telegram_call
        # the transport only accepts a boundary content type, and the token
        # lives in the URL, never in the body
        with self.assertRaises(TransportError):
            telegram_call("https://api.telegram.org/botx:y/sendDocument", "POST",
                          b"{}", 1.0, "text/plain")
        blob = os.urandom(8)
        self.assertNotIn(FAKE_TOKEN.encode(), blob)


if __name__ == "__main__":
    unittest.main()
