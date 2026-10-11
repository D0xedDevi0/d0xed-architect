"""Static GitHub audit: URL parsing, receipts, secret masking, size caps."""
import unittest

from devin.github_audit import (AuditDenied, AuditLimits, audit_public_repo,
                                inspect_tarball, parse_repo_url)
from tests.devin_fixtures import FakeGithub, build_tarball

RAW_API_KEY = "sk-abcdefghijklmnopqrstuvwxyz0123456789"
RAW_PASSWORD = "hunter2secret"
RAW_PAT = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdef"

APP = ('# app.py\n'
       f'API_KEY = "{RAW_API_KEY}"\n'
       f'password = "{RAW_PASSWORD}"\n'
       'import os\n'
       'os.system("echo hi")\n'
       'eval("1+1")\n').encode()

ENVFILE = f'GH_TOKEN = "{RAW_PAT}"\n'.encode()


class TestParseRepoUrl(unittest.TestCase):
    def test_plain(self):
        r = parse_repo_url("https://github.com/owner/repo")
        self.assertEqual((r.owner, r.repo), ("owner", "repo"))

    def test_git_suffix(self):
        r = parse_repo_url("https://github.com/owner/repo.git")
        self.assertEqual(r.repo, "repo")

    def test_dot_dash_names(self):
        r = parse_repo_url("https://github.com/o-1.2/r_3")
        self.assertEqual((r.owner, r.repo), ("o-1.2", "r_3"))

    def test_rejections(self):
        bad = [
            "http://github.com/a/b",                 # not https
            "https://gitlab.com/a/b",                # not github
            "https://github.com/a/b/c",              # extra path
            "https://github.com/a",                  # missing repo
            "https://github.com/a/b?x=1",            # query
            "https://github.com/a/b#frag",           # fragment
            "https://user@github.com/a/b",           # userinfo
            "https://github.com/a/../b",             # traversal-ish name
            "https://github.com/a%20b/repo",         # invalid owner char
            "file:///etc/passwd",                    # non-http scheme
            "",                                       # empty
            "https://raw.githubusercontent.com/a/b",  # raw host, not repo page
        ]
        for u in bad:
            with self.assertRaises(AuditDenied, msg=u):
                parse_repo_url(u)


class TestInspectTarball(unittest.TestCase):
    def test_findings_and_receipts(self):
        tarball = build_tarball({
            "src/app.py": APP,
            ".env": ENVFILE,
            "node_modules/evil.py": b"eval('nope')\n",          # skipped dir
            "src/blob.py": b"print('x')\x00\x01",               # binary -> skipped
            "bin/link.py": ("symlink", "../src/app.py"),        # symlink -> skipped
        })
        out = inspect_tarball(tarball, "owner", "repo", "main", AuditLimits())

        self.assertEqual(out.mode, "static-only")
        self.assertEqual(out.owner, "owner")
        self.assertEqual(out.repo, "repo")
        self.assertEqual(out.ref, "main")

        rules = {f.rule for f in out.findings}
        self.assertIn("secret:openai_key", rules)
        self.assertIn("secret:hardcoded_pw", rules)
        self.assertIn("secret:github_pat", rules)
        self.assertIn("risk:eval_use", rules)
        self.assertIn("risk:os_system", rules)

        # every finding carries file:line + hash receipts
        for f in out.findings:
            self.assertGreaterEqual(f.line, 1)
            self.assertTrue(f.path.endswith((".py", ".env")))
            self.assertRegex(f.file_sha256, r"^[0-9a-f]{64}$")
            self.assertRegex(f.snippet_sha256, r"^[0-9a-f]{64}$")
            self.assertTrue(f.snippet)

        # no scanned path should be from skipped dirs / symlink / binary
        paths = {f.path for f in out.findings}
        self.assertFalse(any("node_modules" in p for p in paths))
        self.assertFalse(any("blob.py" in p for p in paths))
        self.assertFalse(any("link.py" in p for p in paths))

        # secrets never leak into a snippet or detail
        for f in out.findings:
            self.assertNotIn(RAW_API_KEY, f.snippet)
            self.assertNotIn(RAW_API_KEY, f.detail)
            self.assertNotIn(RAW_PASSWORD, f.snippet)
            self.assertNotIn(RAW_PASSWORD, f.detail)
            self.assertNotIn(RAW_PAT, f.snippet)
            self.assertNotIn(RAW_PAT, f.detail)

        # manifest root commits to the findings
        self.assertRegex(out.manifest_root, r"^[0-9a-f]{64}$")
        counts = out.severity_counts()
        self.assertGreaterEqual(counts.get("critical", 0), 2)  # openai_key + github_pat

    def test_file_size_cap(self):
        limits = AuditLimits(max_files=100, max_file_bytes=50, max_total_bytes=10_000,
                             max_findings=50)
        tarball = build_tarball({"src/big.py": b"eval('x')\n" * 100})
        out = inspect_tarball(tarball, "o", "r", "main", limits)
        self.assertEqual(out.files_scanned, 0)
        self.assertTrue(out.truncated)

    def test_max_files_cap(self):
        limits = AuditLimits(max_files=1, max_file_bytes=1000, max_total_bytes=10_000,
                             max_findings=50)
        tarball = build_tarball({"a.py": b"x=1\n", "b.py": b"y=2\n"})
        out = inspect_tarball(tarball, "o", "r", "main", limits)
        self.assertEqual(out.files_scanned, 1)
        self.assertTrue(out.truncated)

    def test_total_bytes_cap(self):
        limits = AuditLimits(max_files=100, max_file_bytes=1000, max_total_bytes=10,
                             max_findings=50)
        tarball = build_tarball({"a.py": b"x=1\n", "b.py": b"y=2\n" * 10})
        out = inspect_tarball(tarball, "o", "r", "main", limits)
        self.assertEqual(out.files_scanned, 1)
        self.assertTrue(out.truncated)

    def test_invalid_archive_denied(self):
        with self.assertRaises(AuditDenied):
            inspect_tarball(b"not a gzip", "o", "r", "main", AuditLimits())


class TestAuditPublicRepo(unittest.TestCase):
    def test_happy_path(self):
        tarball = build_tarball({"src/app.py": APP})
        gh = FakeGithub(tarball=tarball, branch="main")
        out = audit_public_repo("https://github.com/owner/repo", gh, AuditLimits())
        self.assertEqual((out.owner, out.repo, out.ref), ("owner", "repo", "main"))
        self.assertEqual(out.mode, "static-only")
        self.assertGreater(out.files_scanned, 0)
        # fetch hit metadata + tarball, both on allowlisted GitHub hosts only
        self.assertEqual(len(gh.calls), 2)
        for u in gh.calls:
            self.assertTrue("api.github.com" in u or "codeload.github.com" in u, u)

    def test_404_is_denied(self):
        gh = FakeGithub(meta_status=404)
        with self.assertRaises(AuditDenied):
            audit_public_repo("https://github.com/owner/repo", gh, AuditLimits())

    def test_403_is_denied(self):
        gh = FakeGithub(meta_status=403)
        with self.assertRaises(AuditDenied):
            audit_public_repo("https://github.com/owner/repo", gh, AuditLimits())

    def test_bad_url_denied_before_fetch(self):
        gh = FakeGithub(tarball=b"")
        with self.assertRaises(AuditDenied):
            audit_public_repo("https://example.com/a/b", gh, AuditLimits())
        self.assertEqual(gh.calls, [])  # no network attempted for a bad URL


if __name__ == "__main__":
    unittest.main()
