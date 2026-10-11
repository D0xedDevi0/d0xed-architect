"""Benchmark driver failure semantics and matrix contracts."""
import importlib.util
import subprocess
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]

def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "bench" / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

compare = load("benchmark_compare", "compare.py")

class DriverTests(unittest.TestCase):
    def test_nonzero_exit_cannot_smuggle_metrics(self):
        result = SimpleNamespace(returncode=3, stdout='BENCH_JSON {"pages":99,"wall_s":0.01}', stderr='failed')
        with patch.object(compare.subprocess, "run", return_value=result):
            got = compare.run_one("tool", "python", "runner.py", "https://example.org", 2, 1)
        self.assertIn("error", got)
        self.assertEqual(got["process_exit_code"], 3)
        self.assertNotIn("pages", got)
        self.assertIn("driver_wall_s", got)

    def test_timeout_is_a_failure(self):
        with patch.object(compare.subprocess, "run", side_effect=subprocess.TimeoutExpired("cmd", 2)):
            got = compare.run_one("tool", "python", "runner.py", "https://example.org", 2, 1, timeout=2)
        self.assertIn("timeout", got["error"])
        self.assertIsNone(got["process_exit_code"])
        self.assertIn("driver_wall_s", got)

    def test_success_keeps_runner_and_driver_timing_distinct(self):
        result = SimpleNamespace(returncode=0, stdout='BENCH_JSON {"pages":2,"wall_s":0.4}', stderr='')
        with patch.object(compare.subprocess, "run", return_value=result):
            got = compare.run_one("tool", "python", "runner.py", "https://example.org", 2, 1)
        self.assertEqual(got["pages"], 2)
        self.assertEqual(got["wall_s"], 0.4)
        self.assertEqual(got["process_exit_code"], 0)
        self.assertIn("driver_wall_s", got)

if __name__ == "__main__":
    unittest.main()
