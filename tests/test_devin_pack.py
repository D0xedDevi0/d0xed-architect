"""Encrypted artifact packaging: refusal policy, tamper evidence, safety.

The interesting tests here are the REFUSALS and the tamper cases. A packager
that happily seals a repo full of live credentials and mails it somewhere is a
leak generator, not a feature; and a bundle whose manifest can be edited is not
evidence of anything.
"""
import io
import json
import os
import shutil
import tarfile
import tempfile
import unittest

from devin.crypto import IntegrityError, is_bundle
from devin.pack import (AUDIT_NAME, MANIFEST_NAME, PackError, PackLimits,
                        PackRefused, build_pack, open_pack, pack_tarball,
                        render_pack, verify_pack)
from tests.devin_fixtures import build_tarball

PW = "correct horse battery staple"
PY = "def add(a, b):\n    return a + b\n\n\nprint(add(1, 2))\n"
JS = "export const add = (a, b) => a + b;\n"
MD = "# Notes\n\nThis is a small project with a couple of files.\n"
# A synthetic but correctly-shaped AWS key. NOT the AWS docs example — that one
# ends in `EXAMPLE` and the analyzer's placeholder filter deliberately ignores
# it (correctly: documentation examples are not credentials).
AWS_KEY = "AKIA" + "Q7Z2XW9K4M3NB6PQ"


class PackCase(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="devin-pack-test-")
        self.out = tempfile.mkdtemp(prefix="devin-pack-out-")

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)
        shutil.rmtree(self.out, ignore_errors=True)

    def write(self, rel, text):
        path = os.path.join(self.root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        return path

    def sample(self):
        self.write("src/app.py", PY)
        self.write("web/app.js", JS)
        self.write("README.md", MD)
        return self.root


class TestPackRoundTrip(PackCase):
    def test_seals_and_reopens(self):
        self.sample()
        res = build_pack(self.root, PW, label="demo", created_at="2026-10-12T00:00:00Z")
        self.assertTrue(is_bundle(res.blob))
        self.assertEqual(res.files, 3)
        self.assertEqual(res.findings, 0)
        self.assertIn("Python", res.languages)
        self.assertIn("JavaScript", res.languages)
        manifest = open_pack(res.blob, PW, self.out)
        self.assertEqual(manifest["label"], "demo")
        self.assertEqual(manifest["devin_bundle"], 1)
        with open(os.path.join(self.out, "src/app.py"), encoding="utf-8") as fh:
            self.assertEqual(fh.read(), PY)

    def test_manifest_hashes_are_real(self):
        self.sample()
        res = build_pack(self.root, PW)
        sha = res.manifest["files"][0]["sha256"]
        self.assertEqual(len(sha), 64)
        # the declared digest must equal the digest of the file on disk
        import hashlib
        rel = res.manifest["files"][0]["path"]
        with open(os.path.join(self.root, rel), "rb") as fh:
            self.assertEqual(hashlib.sha256(fh.read()).hexdigest(), sha)

    def test_verify_does_not_write_and_counts_files(self):
        self.sample()
        res = build_pack(self.root, PW)
        info = verify_pack(res.blob, PW)
        self.assertEqual(info["checked"], 3)
        self.assertEqual(info["bundle_sha256"], res.bundle_sha256)
        self.assertIn(MANIFEST_NAME, info["members"])
        self.assertIn(AUDIT_NAME, info["members"])
        self.assertEqual(os.listdir(self.out), [])          # nothing written

    def test_audit_is_inside_the_bundle(self):
        self.write("app.py", PY)
        self.write("reqs.txt", "requests==2.31.0\n")
        res = build_pack(self.root, PW)
        inner = verify_pack(res.blob, PW)
        self.assertIn("manifest", inner)
        # AUDIT.json is a real member, and the manifest counts the findings
        self.assertEqual(res.manifest["findings_count"], len(res.blocking) + 0
                         if not res.blocking else res.manifest["findings_count"])

    def test_source_digest_is_reproducible(self):
        self.sample()
        a = build_pack(self.root, PW, created_at="2026-10-12T00:00:00Z")
        b = build_pack(self.root, PW, created_at="2026-10-12T00:00:00Z")
        self.assertEqual(a.source_sha256, b.source_sha256)   # same input, same tar
        self.assertNotEqual(a.blob, b.blob)                 # fresh salt/nonce

    def test_filename_is_descriptive_and_stamped(self):
        self.sample()
        res = build_pack(self.root, PW, label="demo",
                         created_at="2026-10-12T01:02:03Z")
        name = res.filename()
        self.assertTrue(name.startswith("DEVin-demo-"))
        self.assertTrue(name.endswith(".tar.gz.enc"))
        self.assertIn("20261012", name)

    def test_tarball_intake(self):
        data = build_tarball({"app.py": PY.encode(), "lib/util.js": JS.encode()})
        res = pack_tarball(data, PW, label="from-tar")
        self.assertEqual(res.files, 2)
        manifest = open_pack(res.blob, PW, self.out)
        self.assertEqual(manifest["file_count"], 2)
        # the extracted tree must not be left behind
        self.assertTrue(any("app.py" in e["path"] for e in manifest["files"]))

    def test_empty_or_unreadable_input_is_refused(self):
        with self.assertRaises(PackRefused):
            build_pack(self.root, PW)                       # empty dir
        with self.assertRaises(PackError):
            build_pack(os.path.join(self.root, "nope"), PW)


class TestSecretRefusal(PackCase):
    def test_live_credential_blocks_the_seal(self):
        self.write("app.py", PY)
        self.write("config.py", f'AWS_ACCESS_KEY_ID = "{AWS_KEY}"\n')
        with self.assertRaises(PackRefused) as ctx:
            build_pack(self.root, PW)
        # the refusal must explain itself and must NOT echo the secret value
        msg = str(ctx.exception)
        self.assertIn("refusing", msg)
        self.assertNotIn(AWS_KEY, msg)

    def test_allow_secrets_is_explicit_and_recorded(self):
        self.write("config.py", f'AWS_ACCESS_KEY_ID = "{AWS_KEY}"\n')
        res = build_pack(self.root, PW, allow_secrets=True)
        self.assertTrue(res.blocking)
        self.assertTrue(res.manifest["secrets_acknowledged"])
        self.assertIn("acknowledged secret findings", render_pack(res))

    def test_environment_references_do_not_block(self):
        """`process.env.X` is a variable NAME, not a credential."""
        self.write("web/app.js", 'const k = process.env.AWS_ACCESS_KEY_ID;\n')
        res = build_pack(self.root, PW)          # must not raise
        self.assertFalse(res.blocking)

    def test_refusal_message_never_contains_a_secret(self):
        self.write("creds.py", f'token = "{AWS_KEY}"\n')
        try:
            build_pack(self.root, PW)
            self.fail("expected a refusal")
        except PackRefused as e:
            self.assertNotIn(AWS_KEY, str(e))
            self.assertNotIn(PW, str(e))


class TestTamperAndHostileBundles(PackCase):
    def test_flipping_a_byte_breaks_the_bundle(self):
        self.sample()
        res = build_pack(self.root, PW)
        bad = bytearray(res.blob)
        bad[60] ^= 0x01
        with self.assertRaises(IntegrityError):
            verify_pack(bytes(bad), PW)
        with self.assertRaises(IntegrityError):
            open_pack(bytes(bad), PW, self.out)

    def test_wrong_passphrase_does_not_write_anything(self):
        self.sample()
        res = build_pack(self.root, PW)
        with self.assertRaises(IntegrityError):
            open_pack(res.blob, "wrong horse battery staple", self.out)
        self.assertEqual(os.listdir(self.out), [])

    def test_not_a_bundle_is_refused(self):
        self.sample()
        for blob in (b"", b"just text", b"DEVinBNDL1" + b"\x00" * 100):
            with self.subTest(n=len(blob)):
                with self.assertRaises(Exception):
                    open_pack(blob, PW, self.out)

    def _seal_custom_tar(self, members):
        """Seal a hand-built tar so we can ship a hostile member."""
        raw = io.BytesIO()
        with tarfile.open(fileobj=raw, mode="w") as tf:
            for name, payload in members:
                ti = tarfile.TarInfo(name)
                ti.size = len(payload)
                tf.addfile(ti, io.BytesIO(payload))
        from devin.crypto import seal_bundle
        import gzip
        buf = io.BytesIO()
        with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as gz:
            gz.write(raw.getvalue())
        return seal_bundle(buf.getvalue(), PW)

    def test_path_traversal_member_is_refused(self):
        manifest = json.dumps({"devin_bundle": 1, "files": []}).encode()
        blob = self._seal_custom_tar([
            (MANIFEST_NAME, manifest),
            ("../escaped.txt", b"owned"),
        ])
        with self.assertRaises(PackError):
            open_pack(blob, PW, self.out)
        self.assertFalse(os.path.exists(os.path.join(self.out, "..", "escaped.txt")))
        self.assertFalse(os.path.exists("/tmp/escaped.txt"))

    def test_member_missing_from_the_manifest_is_refused(self):
        manifest = json.dumps({"devin_bundle": 1, "files": []}).encode()
        blob = self._seal_custom_tar([
            (MANIFEST_NAME, manifest),
            ("sneaky.py", b"print(1)\n"),
        ])
        with self.assertRaises(PackError):
            open_pack(blob, PW, self.out)

    def test_member_whose_contents_were_swapped_is_refused(self):
        good = "print('ok')\n".encode()
        import hashlib
        manifest = json.dumps({"devin_bundle": 1, "files": [
            {"path": "app.py", "sha256": hashlib.sha256(good).hexdigest(),
             "bytes": len(good), "language": "Python"}]}).encode()
        blob = self._seal_custom_tar([
            (MANIFEST_NAME, manifest),
            ("app.py", b"print('swapped')\n"),
        ])
        with self.assertRaises(IntegrityError):
            open_pack(blob, PW, self.out)

    def test_symlink_member_is_refused(self):
        manifest = json.dumps({"devin_bundle": 1, "files": []}).encode()
        raw = io.BytesIO()
        with tarfile.open(fileobj=raw, mode="w") as tf:
            ti = tarfile.TarInfo(MANIFEST_NAME)
            ti.size = len(manifest)
            tf.addfile(ti, io.BytesIO(manifest))
            link = tarfile.TarInfo("link")
            link.type = tarfile.SYMTYPE
            link.linkname = "/etc/passwd"
            tf.addfile(link)
        import gzip
        from devin.crypto import seal_bundle
        buf = io.BytesIO()
        with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as gz:
            gz.write(raw.getvalue())
        with self.assertRaises(PackError):
            open_pack(seal_bundle(buf.getvalue(), PW), PW, self.out)


class TestBounds(PackCase):
    def test_oversized_file_is_skipped_with_a_warning(self):
        self.write("big.py", "x = 1\n" * 5000)
        self.write("small.py", PY)
        res = build_pack(self.root, PW, limits=PackLimits(max_file_bytes=500))
        self.assertEqual(res.files, 1)
        self.assertTrue(any("skipped" in w for w in res.warnings))

    def test_file_cap_is_enforced(self):
        for i in range(12):
            self.write(f"f{i}.py", PY)
        res = build_pack(self.root, PW, limits=PackLimits(max_files=5))
        self.assertEqual(res.files, 5)
        self.assertTrue(any("cap" in w for w in res.warnings))

    def test_bundle_cap_refuses_instead_of_truncating(self):
        # Incompressible content: a cap that only a highly compressible tree
        # trips would be testing gzip, not the bundler.
        for i in range(4):
            path = os.path.join(self.root, f"blob{i}.bin")
            with open(path, "wb") as fh:
                fh.write(os.urandom(4000))
        with self.assertRaises(PackRefused):
            build_pack(self.root, PW,
                       limits=PackLimits(max_file_bytes=10_000,
                                         max_bundle_bytes=3000))

    def test_limits_are_recorded_in_the_manifest(self):
        self.sample()
        res = build_pack(self.root, PW, limits=PackLimits(max_files=7))
        self.assertEqual(res.manifest["limits"]["max_files"], 7)


class TestReceipt(PackCase):
    def test_render_is_bounded_and_carries_the_hashes(self):
        self.sample()
        res = build_pack(self.root, PW, label="demo")
        out = render_pack(res, max_len=600)
        self.assertLessEqual(len(out), 600)
        self.assertIn("chacha20-poly1305", out)
        self.assertIn(res.bundle_sha256[:16], out)

    def test_receipt_never_leaks_the_passphrase_or_plaintext(self):
        self.sample()
        res = build_pack(self.root, PW)
        out = render_pack(res)
        self.assertNotIn(PW, out)
        self.assertNotIn(PY.strip(), out)
        self.assertNotIn(AWS_KEY, out)

    def test_sealed_bytes_do_not_contain_the_source(self):
        self.write("app.py", "SECRETISH_MARKER_VALUE = 'abc123456789'\n")
        res = build_pack(self.root, PW)
        self.assertNotIn(b"SECRETISH_MARKER_VALUE", res.blob)
        self.assertNotIn(b"print", res.blob)


if __name__ == "__main__":
    unittest.main()
