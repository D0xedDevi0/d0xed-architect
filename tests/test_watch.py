"""Hermetic tests for architect.watch (the standing architecture sentinel).

Every check runs against a throwaway tree under the scratch dir. No network, no writes
outside the per-test temp directory, and the audited tree is never modified -- an
assertion here would be worthless if the test itself changed the thing under test.
"""
import json
import os
import shutil
import tempfile
import unittest

from architect import watch

APP = 'import os\n\nif __name__ == "__main__":\n    print("a")\n'


class WatchTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="watch-test-")
        self.tree = os.path.join(self.tmp, "tree")
        self.state = os.path.join(self.tmp, "state")
        os.makedirs(self.tree)
        os.makedirs(self.state)
        with open(os.path.join(self.tree, "app.py"), "w", encoding="utf-8") as fh:
            fh.write(APP)
        self.base = os.path.join(self.state, "base.json")
        self.log = os.path.join(self.state, "drift.log")
        self.keys = os.path.join(self.state, "keys")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    # helpers -----------------------------------------------------------------
    def _run(self, **kw):
        return watch.run(self.tree, self.base, self.log, self.keys, **kw)

    def _add(self, name, body="def f():\n    return 1\n"):
        with open(os.path.join(self.tree, name), "w", encoding="utf-8") as fh:
            fh.write(body)

    def _log_text(self):
        with open(self.log, encoding="utf-8") as fh:
            return fh.read()

    # checks ------------------------------------------------------------------
    def test_01_first_run_establishes_a_signed_baseline(self):
        code, report = self._run()
        self.assertEqual(code, 0)
        self.assertEqual(report["status"], "baseline-established")
        with open(self.base, encoding="utf-8") as fh:
            base = json.load(fh)
        self.assertIn("sig", base, "baseline must be signed, not bare")
        self.assertEqual(base["sig"]["alg"], "ed25519")
        self.assertIn("BASELINE ESTABLISHED", self._log_text())

    def test_02_unchanged_tree_is_clean_and_silent(self):
        self._run()
        code, report = self._run()
        self.assertEqual(code, 0, "a clean tree must not report drift")
        self.assertEqual(report["status"], "clean")
        self.assertEqual(report["drift"]["drift"], [])
        self.assertTrue(report["drift"]["clean"])

    def test_03_added_module_is_notable_not_breaking(self):
        self._run()
        self._add("extra.py")
        code, report = self._run()
        self.assertEqual(code, 3)
        self.assertEqual(report["counts"]["notable"], 1)
        self.assertEqual(report["counts"]["breaking"], 0)
        kinds = [i["kind"] for i in report["drift"]["drift"]]
        self.assertEqual(kinds, ["module_added"])
        self.assertIn("extra.py", self._log_text())

    def test_04_removed_entrypoint_file_is_breaking(self):
        self._run()
        os.remove(os.path.join(self.tree, "app.py"))
        code, report = self._run()
        self.assertEqual(code, 1, "a removed module must be breaking")
        # Deleting app.py drops three facts at once: the module, its entrypoint, and the
        # import edge it carried. Only the first two are breaking -- the lost import edge is
        # informational. Assert the severities that matter, not an exhaustive kind list.
        by_severity = {}
        for item in report["drift"]["drift"]:
            by_severity.setdefault(item["severity"], set()).add(item["kind"])
        self.assertEqual(by_severity.get("breaking"), {"module_removed", "entrypoint_removed"})
        self.assertEqual(report["counts"]["breaking"], 2)
        # A lost import edge is notable (not breaking): the sentinel's own _KINDS table
        # ranks removed imports above added ones. Assert the real severity, not a guess.
        self.assertIn("import_removed", by_severity.get("notable", set()))

    def test_05_adopt_reports_then_rolls_the_baseline_forward(self):
        self._run()
        self._add("extra.py")
        code, report = self._run(adopt=True)
        self.assertEqual(code, 0, "an explicit adopt must not alarm every night")
        self.assertIn("adopted", report)
        self.assertIn("BASELINE ADOPTED", self._log_text())
        # The drift was still reported before adopting -- never silently absorbed.
        self.assertEqual(report["counts"]["notable"], 1)
        code2, report2 = self._run()
        self.assertEqual(code2, 0)
        self.assertEqual(report2["status"], "clean")

    def test_06_adopt_is_not_a_silent_repair(self):
        """Adopting must not run before the comparison: the change is always logged first."""
        self._run()
        self._add("extra.py")
        self._run(adopt=True)
        text = self._log_text()
        self.assertLess(text.index("module_added"), text.index("BASELINE ADOPTED"),
                        "the drift entry must be logged before the adoption entry")

    def test_07_tampered_baseline_is_refused_not_repaired(self):
        self._run()
        with open(self.base, encoding="utf-8") as fh:
            base = json.load(fh)
        base["modules"]["app.py"] = "0" * 64          # forge a module digest
        with open(self.base, "w", encoding="utf-8") as fh:
            json.dump(base, fh)
        before = base["arch_root"]
        code, report = self._run()
        self.assertEqual(code, 2)
        self.assertEqual(report["status"], "baseline-refused")
        self.assertIn("BASELINE REFUSED", self._log_text())
        with open(self.base, encoding="utf-8") as fh:
            self.assertEqual(json.load(fh)["arch_root"], before,
                             "a refused baseline must be left exactly as found")

    def test_08_state_inside_the_audited_tree_is_refused(self):
        inside = os.path.join(self.tree, ".architect-baseline.json")
        code = watch.main([self.tree, "--baseline", inside])
        self.assertEqual(code, 2, "state must never be written into the audited tree")
        self.assertFalse(os.path.exists(inside))

    def test_09_failed_log_write_does_not_mask_the_result(self):
        self._run()
        self._add("extra.py")
        blocked = os.path.join(self.state, "blocked.log")
        os.makedirs(blocked)                            # append to a directory always fails
        code, report = watch.run(self.tree, self.base, blocked, self.keys)
        self.assertEqual(code, 3, "the drift verdict must survive an unwritable log")
        self.assertEqual(report["status"], "drift")
        self.assertTrue(report.get("warnings"), "the failed write must be reported, not swallowed")

    def test_10_never_touches_the_audited_tree(self):
        self._run()
        self._add("extra.py")
        before = {}
        for folder, _dirs, files in os.walk(self.tree):
            for name in files:
                path = os.path.join(folder, name)
                with open(path, "rb") as fh:
                    before[path] = fh.read()
        self._run(adopt=True)
        after = {}
        for folder, _dirs, files in os.walk(self.tree):
            for name in files:
                path = os.path.join(folder, name)
                with open(path, "rb") as fh:
                    after[path] = fh.read()
        self.assertEqual(before, after, "the sentinel must be strictly read-only on the tree")

    def test_11_summary_line_is_first_in_the_log_entry(self):
        self._run()
        self._add("extra.py")
        self._run()
        lines = [ln for ln in self._log_text().splitlines() if "drift" in ln]
        self.assertTrue(lines, "a drift run must log a summary line")
        self.assertRegex(lines[-1], r"files=\d+\s+\d+ drift")

    def test_12_missing_tree_is_an_error_not_a_crash(self):
        code, report = watch.run(os.path.join(self.tmp, "nope"), self.base, self.log, self.keys)
        self.assertEqual(code, 2)
        self.assertIn("error", report)


if __name__ == "__main__":
    unittest.main(verbosity=2)