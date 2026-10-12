"""Uploaded code sets: intake boundaries, traversal safety, and the bot path.

The user-facing promise is "send me your private repo and I'll audit it (and
hand you back an encrypted copy)". Almost all of the risk here is in the edges:
a file that lies about what it is, a filename that fights the shell, an archive
member that tries to escape the temp dir, a declared size that doesn't match the
bytes. Those refusals are what these tests pin down.
"""
import io
import os
import unittest
import zipfile
from types import SimpleNamespace

from devin.crypto import is_bundle
from devin.upload import (MAX_UPLOAD_BYTES, UploadDenied, extension_of, intake,
                          parse_document, safe_file_path, sniff)
from tests.devin_fixtures import (GROUP_ID, USER_ID, dm_update, group_update)

PY = b"import os\n\n\ndef main():\n    return os.getpid()\n"
JS = b"export const clamp = (n) => Math.min(1, n);\n"
PW = "correct horse battery staple"


def make_zip(files=None, traversal=None, symlink=None, stored=False):
    buf = io.BytesIO()
    mode = zipfile.ZIP_STORED if stored else zipfile.ZIP_DEFLATED
    with zipfile.ZipFile(buf, "w", mode) as z:
        for name, data in (files or {}).items():
            z.writestr(name, data)
        if traversal:
            z.writestr(traversal, b"owned")
        if symlink:
            info = zipfile.ZipInfo(symlink)
            info.external_attr = (0o120777 << 16)
            z.writestr(info, "/etc/passwd")
    return buf.getvalue()


def make_tgz(files=None):
    import gzip
    import tarfile
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as tf:
        for name, data in (files or {}).items():
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))
    out = io.BytesIO()
    with gzip.GzipFile(fileobj=out, mode="wb", mtime=0) as gz:
        gz.write(raw.getvalue())
    return out.getvalue()


class TestDocumentParsing(unittest.TestCase):
    def doc(self, **kw):
        base = {"file_id": "F1", "file_name": "repo.zip", "file_size": 1000}
        base.update(kw)
        return {"document": base}

    def test_accepts_zip_and_tgz(self):
        self.assertEqual(parse_document(self.doc()).kind, "zip")
        self.assertEqual(parse_document(self.doc(file_name="r.tgz")).kind, "tgz")
        self.assertEqual(parse_document(self.doc(file_name="r.tar.gz")).kind, "tgz")

    def test_refuses_unsupported_formats(self):
        for name in ("repo.rar", "repo.7z", "notes.txt", "payload.exe",
                     "archive.tar", "repo.zip.exe", ""):
            with self.subTest(name=name):
                with self.assertRaises(UploadDenied):
                    parse_document(self.doc(file_name=name))

    def test_refuses_hostile_filenames(self):
        for name in ("../evil.zip", "a/b.zip", "re${IFS}po.zip", "repo;rm -rf.zip",
                     "repo\x00.zip", ".zip", "x" * 300 + ".zip"):
            with self.subTest(name=name):
                with self.assertRaises(UploadDenied):
                    parse_document(self.doc(file_name=name))

    def test_refuses_oversize_and_empty(self):
        with self.assertRaises(UploadDenied):
            parse_document(self.doc(file_size=MAX_UPLOAD_BYTES + 1))
        with self.assertRaises(UploadDenied):
            parse_document(self.doc(file_size=0))

    def test_refuses_non_document_messages(self):
        with self.assertRaises(UploadDenied):
            parse_document({})
        with self.assertRaises(UploadDenied):
            parse_document({"photo": [{"file_id": "x"}]})

    def test_extension_of(self):
        self.assertEqual(extension_of("A.ZIP"), ".zip")
        self.assertEqual(extension_of("a.tar.gz"), ".tar.gz")
        self.assertEqual(extension_of("a.gz"), "")


class TestFilePaths(unittest.TestCase):
    def test_accepts_telegram_shapes(self):
        self.assertEqual(safe_file_path("documents/file_12.zip"),
                         "documents/file_12.zip")
        self.assertEqual(safe_file_path("files/file_1"), "files/file_1")

    def test_refuses_anything_else(self):
        for path in (None, "", "/etc/passwd", "documents/../../etc/passwd",
                     "documents/sub/file.zip", "http://evil.test/x",
                     "documents/file.zip?x=1", "photos/file_1.jpg",
                     "documents/" + "a" * 100 + ".zip", 42, b"documents/x.zip"):
            with self.subTest(path=path):
                self.assertIsNone(safe_file_path(path))


class TestMagicBytes(unittest.TestCase):
    def test_renamed_binaries_are_refused(self):
        self.assertFalse(sniff("zip", b"\x7fELF\x02\x01\x01\x00"))
        self.assertFalse(sniff("zip", b"\xff\xd8\xff\xe0" + b"\x00" * 20))
        self.assertFalse(sniff("tgz", b"not a gzip at all"))
        self.assertFalse(sniff("zip", b""))

    def test_real_archives_pass(self):
        self.assertTrue(sniff("zip", make_zip({"a.py": PY})))
        self.assertTrue(sniff("tgz", make_tgz({"a.py": PY})))


class TestIntakeSafety(unittest.TestCase):
    def test_keeps_the_users_own_layout(self):
        """An uploaded archive is NOT a GitHub tarball: src/app.py must stay."""
        root, trunc = intake("zip", make_zip({"src/app.py": PY,
                                              "lib/util.js": JS}))
        self.addCleanup(lambda: __import__("shutil").rmtree(root, True))
        self.assertTrue(os.path.exists(os.path.join(root, "src", "app.py")))
        self.assertTrue(os.path.exists(os.path.join(root, "lib", "util.js")))
        self.assertFalse(trunc)

    def test_tarball_upload_keeps_layout_too(self):
        root, _ = intake("tgz", make_tgz({"src/app.py": PY}))
        self.addCleanup(lambda: __import__("shutil").rmtree(root, True))
        self.assertTrue(os.path.exists(os.path.join(root, "src", "app.py")))

    def test_traversal_member_cannot_escape(self):
        root, _ = intake("zip", make_zip({"ok.py": PY}, traversal="../evil.txt"))
        self.addCleanup(lambda: __import__("shutil").rmtree(root, True))
        self.assertFalse(os.path.exists(os.path.join(root, "..", "evil.txt")))
        self.assertFalse(os.path.exists(os.path.join(os.path.dirname(root),
                                                     "evil.txt")))
        self.assertTrue(os.path.exists(os.path.join(root, "ok.py")))

    def test_symlink_member_is_skipped(self):
        root, _ = intake("zip", make_zip({"ok.py": PY}, symlink="link"))
        self.addCleanup(lambda: __import__("shutil").rmtree(root, True))
        self.assertFalse(os.path.exists(os.path.join(root, "link")))

    def test_skip_dirs_are_not_extracted(self):
        root, _ = intake("zip", make_zip({"node_modules/x/index.js": JS,
                                          "app.py": PY}))
        self.addCleanup(lambda: __import__("shutil").rmtree(root, True))
        self.assertFalse(os.path.exists(os.path.join(root, "node_modules")))
        self.assertTrue(os.path.exists(os.path.join(root, "app.py")))

    def test_unopenable_bytes_are_refused(self):
        with self.assertRaises(UploadDenied):
            intake("tgz", b"\x1f\x8b" + b"\x00" * 40)     # magic ok, garbage in

    def test_caps_apply(self):
        from devin.analysis import AnalysisLimits
        root, trunc = intake("zip", make_zip({f"f{i}.py": PY for i in range(20)}),
                             AnalysisLimits(max_files=5))
        self.addCleanup(lambda: __import__("shutil").rmtree(root, True))
        self.assertTrue(trunc)
        self.assertLessEqual(len(os.listdir(root)), 5)


# ── bot path ────────────────────────────────────────────────────────────────

class FileGet:
    """Injected `file_get(url, timeout) -> Response`."""

    def __init__(self, body=b"", status=200):
        self.body = body
        self.status = status
        self.calls = []

    def __call__(self, url, timeout):
        self.calls.append(url)
        return SimpleNamespace(status=self.status, body=self.body)


class BotTransport:
    def __init__(self, getfile_path="documents/file_1.zip"):
        self.calls = []
        self.getfile_path = getfile_path

    def __call__(self, url, method, body, timeout, content_type="application/json"):
        self.calls.append({"url": url, "body": body or b"",
                           "ctype": content_type})
        if url.endswith("/getFile"):
            res = {"ok": True, "result": {"file_id": "F1",
                                          "file_path": self.getfile_path}}
        else:
            res = {"ok": True, "result": {}}
        return SimpleNamespace(status=200,
                               body=__import__("json").dumps(res).encode())

    def texts(self):
        return [c["body"].decode("utf-8", "replace") for c in self.calls]

    def documents(self):
        return [c for c in self.calls if c["url"].endswith("/sendDocument")]


def doc_update(user_id, body, name="repo.zip", size=None, update_id=1,
               text=""):
    u = dm_update(update_id, user_id, text)
    u["message"]["document"] = {"file_id": "F1", "file_name": name,
                                "file_size": len(body) if size is None else size}
    return u


def make_bot(body=b"", passphrase=PW, get=None, transport=None, getfile_path=None):
    from devin.bot import DevinBot
    from devin.config import Config, Limits
    cfg = Config(token="1:" + "A" * 35, allowed_user_ids=(USER_ID,),
                 allowed_group_ids=(GROUP_ID,), limits=Limits(),
                 bot_id=None, bot_username="DEVinlooperbot")
    tg = transport or BotTransport(getfile_path or "documents/file_1.zip")
    fg = get if get is not None else FileGet(body)
    return DevinBot(cfg, tg, None, None, bundle_passphrase=passphrase,
                    file_get=fg), tg


class TestBotUpload(unittest.TestCase):
    def test_audits_and_seals_a_dm_upload(self):
        body = make_zip({"src/app.py": PY, "lib/util.js": JS})
        bot, tg = make_bot(body)
        r = bot.handle_update(doc_update(USER_ID, body))
        self.assertTrue(r.detail.startswith("upload:2f"), r.detail)
        self.assertTrue(r.detail.endswith(":sealed"))
        self.assertEqual(len(tg.documents()), 1)
        # the multipart part carries a real SEALED bundle: opaque by design,
        # so the only honest check is opening it with the passphrase
        body_bytes = tg.documents()[0]["body"]
        marker = b'name="document"; filename="'
        start = body_bytes.index(marker)
        head_end = body_bytes.index(b"\r\n\r\n", start) + 4
        blob = body_bytes[head_end:body_bytes.rindex(b"\r\n--")]
        self.assertTrue(is_bundle(blob))
        self.assertNotIn(b"os.getpid", blob)          # no plaintext inside
        from devin.pack import open_pack
        import tempfile
        dest = tempfile.mkdtemp(prefix="devin-upload-open-")
        self.addCleanup(lambda: __import__("shutil").rmtree(dest, True))
        manifest = open_pack(blob, PW, dest)
        self.assertEqual(manifest["file_count"], 2)
        self.assertTrue(os.path.exists(os.path.join(dest, "src", "app.py")))

    def test_audit_only_when_no_sealing_key(self):
        body = make_zip({"src/app.py": PY})
        bot, tg = make_bot(body, passphrase=None)
        r = bot.handle_update(doc_update(USER_ID, body))
        self.assertTrue(r.detail.startswith("upload:1f"))
        self.assertFalse(r.detail.endswith(":sealed"))
        self.assertEqual(tg.documents(), [])

    def test_group_upload_is_not_downloaded(self):
        body = make_zip({"src/app.py": PY})
        bot, tg = make_bot(body)
        u = group_update(1, USER_ID, GROUP_ID, "", reply_to_bot=False)
        u["message"]["document"] = {"file_id": "F1", "file_name": "repo.zip",
                                    "file_size": len(body)}
        r = bot.handle_update(u)
        self.assertEqual(r.detail, "not addressed in group")
        self.assertEqual(tg.documents(), [])

    def test_disabled_intake_refuses_clearly(self):
        body = make_zip({"a.py": PY})
        bot, tg = make_bot(body, get=None)
        bot.file_get = None
        r = bot.handle_update(doc_update(USER_ID, body))
        self.assertEqual(r.detail, "upload-disabled")
        self.assertEqual(tg.documents(), [])

    def test_renamed_binary_is_refused(self):
        bot, tg = make_bot(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 100)
        r = bot.handle_update(doc_update(USER_ID, b"x"))
        self.assertEqual(r.detail, "upload-notarchive")
        self.assertEqual(tg.documents(), [])

    def test_bad_file_path_is_refused(self):
        body = make_zip({"a.py": PY})
        bot, tg = make_bot(body, getfile_path="../../etc/passwd")
        r = bot.handle_update(doc_update(USER_ID, body))
        self.assertEqual(r.detail, "upload-badpath")
        self.assertEqual(tg.documents(), [])

    def test_actual_bytes_over_the_cap_are_refused(self):
        body = make_zip({"a.py": PY})
        bot, tg = make_bot(body, transport=BotTransport())
        bot.transport_max_bytes = 10          # pretend the transport is tiny
        r = bot.handle_update(doc_update(USER_ID, body, size=5))
        self.assertEqual(r.detail, "upload-toobig")
        self.assertEqual(tg.documents(), [])

    def test_live_credentials_stop_the_seal_but_the_audit_still_lands(self):
        body = make_zip({"config.py": b'AWS_ACCESS_KEY_ID = "AKIAQ7Z2XW9K4M3NB6PQ"\n'})
        bot, tg = make_bot(body)
        r = bot.handle_update(doc_update(USER_ID, body))
        self.assertTrue(r.detail.startswith("upload:"))
        self.assertFalse(r.detail.endswith(":sealed"))
        self.assertEqual(tg.documents(), [])
        self.assertTrue(any("not sealed" in t for t in tg.texts()))

    def test_no_passphrase_or_token_leaks_into_the_reply(self):
        body = make_zip({"src/app.py": PY})
        bot, tg = make_bot(body)
        bot.handle_update(doc_update(USER_ID, body))
        for text in tg.texts():
            self.assertNotIn(PW, text)
            self.assertNotIn("1:" + "A" * 35, text)


if __name__ == "__main__":
    unittest.main()
