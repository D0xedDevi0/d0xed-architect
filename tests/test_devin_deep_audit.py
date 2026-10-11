"""Deep static architecture/debug report: facts, receipts, refusals, no leak."""
import unittest

from devin.deep_audit import deep_repo_report
from devin.github_audit import AuditDenied, AuditLimits
from devin.report import render_deep_report
from tests.devin_fixtures import FAKE_GITHUB_TOKEN, FakeGithub, build_tarball

# Built at runtime so no contiguous AWS-shaped literal sits in the source
# (gitleaks would flag it); the concatenated value still matches the scanner's
# aws_key rule at test time. Not a credential.
SECRET = ("AKIA" + "ABCDEFGHIJKLMNOP").encode()


def sample_tarball():
    return build_tarball({
        "src/app.py": (b"import os\nimport src.util\nKEY = b'" + SECRET
                       + b"'\n# TODO wire it up\n"),
        "src/util.py": b"def f():\n    return eval('1')\n",
        "src/a.py": b"import src.b\n",          # a <-> b import cycle
        "src/b.py": b"import src.a\n",
        "requirements.txt": b"flask==3.0\nrequests\n",
        "package.json": b'{"dependencies":{"react":"18.0.0"}}',
        ".github/workflows/ci.yml": b"on: push\n",
        "tests/test_app.py": b"def test_x():\n    assert True\n",
    })


class TestDeepReport(unittest.TestCase):
    def test_architecture_facts(self):
        gh = FakeGithub(tarball=sample_tarball(), branch="main")
        rep = deep_repo_report("https://github.com/owner/repo", gh)
        self.assertEqual((rep.owner, rep.repo, rep.ref), ("owner", "repo", "main"))
        self.assertIn(".py", rep.languages)
        self.assertIn("requirements.txt", rep.manifests)
        self.assertIn("flask==3.0", rep.manifests["requirements.txt"])
        self.assertIn("react", rep.manifests["package.json"])
        self.assertTrue(any(w.endswith("ci.yml") for w in rep.workflows))
        self.assertTrue(any(t.endswith("test_app.py") for t in rep.tests))
        self.assertGreaterEqual(rep.todo_count, 1)
        self.assertTrue(rep.cycles)                     # a <-> b
        self.assertTrue(rep.findings)                   # secret + eval risk
        for f in rep.findings:
            self.assertGreaterEqual(f.line, 1)
            self.assertTrue(f.file_sha256 and f.snippet_sha256)

    def test_render_is_static_only_and_masks_secret(self):
        gh = FakeGithub(tarball=sample_tarball())
        rep = deep_repo_report("https://github.com/owner/repo", gh)
        text = render_deep_report(rep)
        self.assertIn("STATIC-ONLY", text)
        self.assertIn("manifest:", text)
        self.assertNotIn(SECRET.decode(), text)         # never raw in chat

    def test_non_github_refused_without_fetch(self):
        gh = FakeGithub(tarball=sample_tarball())
        with self.assertRaises(AuditDenied):
            deep_repo_report("https://example.com/a/b", gh)
        self.assertEqual(gh.calls, [])

    def test_private_without_token_refused(self):
        gh = FakeGithub(tarball=sample_tarball(), private=True)
        with self.assertRaises(AuditDenied):
            deep_repo_report("https://github.com/o/r", gh)

    def test_private_with_token_audited_and_token_never_leaks(self):
        gh = FakeGithub(tarball=sample_tarball(), private=True)
        rep = deep_repo_report("https://github.com/o/r", gh,
                               token=FAKE_GITHUB_TOKEN)
        text = render_deep_report(rep)
        self.assertNotIn(FAKE_GITHUB_TOKEN, text)
        # an Authorization header is only ever sent to the two token hosts
        for url, headers in gh.headers_seen:
            auth = None
            for k, v in (headers or {}).items():
                if k.lower() == "authorization":
                    auth = v
            if auth is not None:
                self.assertTrue(url.startswith("https://api.github.com/")
                                or url.startswith("https://codeload.github.com/"))
                self.assertEqual(auth, f"Bearer {FAKE_GITHUB_TOKEN}")

    def test_traversal_member_is_skipped(self):
        gh = FakeGithub(tarball=build_tarball({"../evil.py": b"x = 1\n"}))
        rep = deep_repo_report("https://github.com/o/r", gh)
        self.assertEqual(rep.files_scanned, 0)
        self.assertEqual(rep.findings, [])

    def test_symlink_member_is_skipped(self):
        gh = FakeGithub(tarball=build_tarball({"link.py": ("symlink", "/etc/passwd")}))
        rep = deep_repo_report("https://github.com/o/r", gh)
        self.assertEqual(rep.files_scanned, 0)

    def test_oversized_archive_refused(self):
        gh = FakeGithub(tarball=sample_tarball())
        with self.assertRaises(AuditDenied):
            deep_repo_report("https://github.com/o/r", gh,
                             limits=AuditLimits(max_total_bytes=10))

    def test_unreadable_archive_refused(self):
        gh = FakeGithub(tarball=b"not a tarball")
        with self.assertRaises(AuditDenied):
            deep_repo_report("https://github.com/o/r", gh)


if __name__ == "__main__":
    unittest.main()
