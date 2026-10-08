"""Sentinel swarm-node contract: hermetic trees, injected event bus, no network.

The node wraps sentinel.capture/diff/verify_baseline. These tests assert the
pick-up-and-place behaviour: the node runs like any other, emits real events,
produces genuine receipts only where a current file exists, and reports
removals as stats (breaking count) rather than fabricated findings.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from architect import events, nodes, sentinel  # noqa: E402


def write(root, name, text):
    path = os.path.join(root, name)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


def baseline_path(tmp, tree):
    base = sentinel.capture(tree)
    path = os.path.join(tmp, "baseline.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(base, fh)
    return path


class SentinelNodeTests(unittest.TestCase):
    def _tree(self, tmp):
        tree = os.path.join(tmp, "tree")
        os.makedirs(tree)
        return tree

    def test_no_baseline_runs_clean(self):
        with tempfile.TemporaryDirectory(prefix="d0x-snode-") as tmp:
            tree = self._tree(tmp)
            write(tree, "app.py", "print('hello')\n")
            res = nodes.node_sentinel(tree)
            self.assertEqual(res.findings, [])
            self.assertEqual(res.stats["baseline"], "none")
            self.assertGreaterEqual(res.stats["modules"], 1)
            self.assertIn("note", res.stats)

    def test_new_file_yields_one_evidence_backed_finding(self):
        with tempfile.TemporaryDirectory(prefix="d0x-snode-") as tmp:
            tree = self._tree(tmp)
            write(tree, "app.py", "print('hello')\n")
            base = baseline_path(tmp, tree)
            os.environ["ARCHITECT_BASELINE"] = base
            try:
                write(tree, "new.py", "x = 1\n")
                res = nodes.node_sentinel(tree)
            finally:
                os.environ.pop("ARCHITECT_BASELINE", None)
            self.assertEqual(len(res.findings), 1)
            f = res.findings[0]
            self.assertEqual(f.path, "new.py")
            self.assertEqual(f.line, 1)
            self.assertEqual(len(f.file_sha256), 64)
            self.assertEqual(len(f.snippet_sha256), 64)
            self.assertTrue(f.snippet)
            self.assertEqual(f.node, "sentinel")

    def test_deleted_file_is_stats_not_finding(self):
        with tempfile.TemporaryDirectory(prefix="d0x-snode-") as tmp:
            tree = self._tree(tmp)
            write(tree, "app.py", "print('hello')\n")
            write(tree, "gone.py", "pass\n")
            base = baseline_path(tmp, tree)
            os.environ["ARCHITECT_BASELINE"] = base
            try:
                os.remove(os.path.join(tree, "gone.py"))
                res = nodes.node_sentinel(tree)
            finally:
                os.environ.pop("ARCHITECT_BASELINE", None)
            self.assertEqual(res.findings, [])
            self.assertIn("gone.py", res.stats.get("removed", []))
            self.assertEqual(res.stats.get("breaking", 0), 1)

    def test_run_node_emits_start_then_done(self):
        with tempfile.TemporaryDirectory(prefix="d0x-snode-") as tmp:
            tree = self._tree(tmp)
            write(tree, "app.py", "print('hello')\n")
            bus = events.EventBus()
            nodes.run_node("sentinel", tree, bus)
            kinds = [e.kind for e in bus.history]
            start = kinds.index(events.NODE_START)
            done = kinds.index(events.NODE_DONE)
            self.assertLess(start, done)
            starts = bus.of(events.NODE_START)
            self.assertEqual(starts[0].node, "sentinel")

    def test_swarm_entrypoint_end_to_end(self):
        with tempfile.TemporaryDirectory(prefix="d0x-snode-") as tmp:
            tree = self._tree(tmp)
            write(tree, "app.py", "print('hello')\n")
            write(tree, "extra.py", "y = 2\n")
            base = baseline_path(tmp, tree)
            os.environ["ARCHITECT_BASELINE"] = base
            try:
                write(tree, "fresh.py", "z = 3\n")
                bus = events.EventBus()
                out = nodes.run_swarm(tree, ["sentinel"], bus)
            finally:
                os.environ.pop("ARCHITECT_BASELINE", None)
            self.assertIn("sentinel", out["results"])
            self.assertEqual(len(out["results"]["sentinel"].findings), 1)
            self.assertTrue(bus.of(events.NODE_START))
            self.assertTrue(bus.of(events.NODE_DONE))
            self.assertEqual(len(bus.of(events.SWARM_DONE)), 1)

    def test_symlink_and_odd_paths_do_not_escape_or_crash(self):
        with tempfile.TemporaryDirectory(prefix="d0x-snode-") as tmp:
            tree = self._tree(tmp)
            write(tree, "app.py", "print('hello')\n")
            outside = os.path.join(tmp, "secret.txt")
            with open(outside, "w", encoding="utf-8") as fh:
                fh.write("SHHH\n")
            # A symlinked file pointing outside the tree, plus an odd-named dir.
            os.symlink(outside, os.path.join(tree, "leak.py"))
            odd = os.path.join(tree, "we ird dir")
            os.makedirs(odd)
            write(tree, "we ird dir/ok.py", "pass\n")
            res = nodes.node_sentinel(tree)  # no baseline: must not crash
            self.assertEqual(res.findings, [])
            self.assertNotIn("leak.py", res.stats.get("removed", []))
            # Nothing may cite a path outside the tree.
            self.assertTrue(all(not f.path.startswith(("/", ".."))
                                for f in res.findings))

    def test_tampered_baseline_is_refused(self):
        with tempfile.TemporaryDirectory(prefix="d0x-snode-") as tmp:
            tree = self._tree(tmp)
            write(tree, "app.py", "print('hello')\n")
            path = baseline_path(tmp, tree)
            keydir = os.path.join(os.path.dirname(path), ".architect-keys")
            base = sentinel.sign_baseline(sentinel.capture(tree), keydir)
            base["modules"]["app.py"] = "0" * 64
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(base, fh)
            os.environ["ARCHITECT_BASELINE"] = path
            try:
                with self.assertRaises(ValueError):
                    nodes.node_sentinel(tree)
            finally:
                os.environ.pop("ARCHITECT_BASELINE", None)


if __name__ == "__main__":
    unittest.main()
