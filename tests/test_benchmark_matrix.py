"""Benchmark driver failure semantics and matrix contracts."""
import importlib.util
import subprocess
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]

def load(name, filename):
    import sys
    bench = str(ROOT / "bench")
    if bench not in sys.path:
        sys.path.insert(0, bench)
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

class MatrixTests(unittest.TestCase):
    def test_aggregation_and_immutable_output(self):
        import tempfile
        matrix = load("benchmark_matrix", "benchmark_matrix.py")
        targets = [{"name": "s", "url": "https://example.org", "kind": "static", "content_marker": "VISIBLE"}]
        mock_metrics = {"pages": 1, "content_marker_pages": 0, "process_exit_code": 0,
                        "wall_s": 1.2, "driver_wall_s": 1.4, "peak_rss_mb": 30}
        with tempfile.TemporaryDirectory() as td, patch.object(matrix.os.path, "isfile", return_value=True), patch.object(matrix, "run_one", return_value=mock_metrics):
            dest = str(Path(td) / "results.json")
            result = matrix.run_matrix(targets, max_pages=2, depth=0, repetitions=1, output=dest)
            self.assertEqual(len(result["runs"]), 3)
            self.assertTrue(all(r["frontier_warning"] for r in result["runs"]))
            self.assertFalse(any(r["content_present"] for r in result["runs"]))
            self.assertEqual(result["runs"][0]["mode"], "architect-http")
            self.assertEqual(result["runs"][1]["mode"], "architect-ladder")
            self.assertEqual(result["runs"][2]["mode"], "crawl4ai-browser")
            with self.assertRaises(FileExistsError):
                matrix.run_matrix(targets, max_pages=2, depth=0, repetitions=1, output=dest)
            self.assertEqual(__import__("json").loads(Path(dest).read_text()), result)

    def test_failures_have_no_invented_content(self):
        import tempfile
        matrix = load("benchmark_matrix", "benchmark_matrix.py")
        targets = [{"name": "s", "url": "https://example.org", "kind": "static", "content_marker": "VISIBLE"}]
        with tempfile.TemporaryDirectory() as td, patch.object(matrix.os.path, "isfile", return_value=True), patch.object(matrix, "run_one", return_value={"error": "runner exited nonzero", "process_exit_code": 1, "driver_wall_s": 0.1}):
            result = matrix.run_matrix(targets, max_pages=2, depth=0, repetitions=1, output=str(Path(td) / "fail.json"))
        self.assertFalse(any(r["success"] for r in result["runs"]))
        self.assertTrue(all(r["content_present"] is None for r in result["runs"]))
        self.assertTrue(all("pages" not in r["metrics"] for r in result["runs"]))

    def test_local_fixture_guards_and_js_content(self):
        import tempfile
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        matrix = load("benchmark_matrix", "benchmark_matrix.py")
        denied = []
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass
            def do_GET(self):
                if self.path == "/robots.txt":
                    body = b"User-agent: *\nDisallow: /private\n"
                elif self.path == "/private":
                    denied.append(self.path)
                    body = b"PRIVATE"
                elif self.path == "/static":
                    body = b'<html><body>STATIC_VISIBLE <a href="/private">private</a><a href="/redirect">redirect</a></body></html>'
                elif self.path == "/redirect":
                    self.send_response(302)
                    self.send_header("Location", "/private")
                    self.end_headers()
                    return
                elif self.path == "/js":
                    body = b'<html><body><div id="root"></div><script>document.getElementById("root").textContent="JS_"+"VISIBLE"</script><a href="/private">private</a></body></html>'
                else:
                    body = b""
                self.send_response(200 if body else 404)
                self.send_header("Content-Type", "text/html" if self.path != "/robots.txt" else "text/plain")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            base = f"http://127.0.0.1:{server.server_port}"
            targets = [{"name": "static", "url": base + "/static", "kind": "static", "content_marker": "STATIC_VISIBLE"},
                       {"name": "js", "url": base + "/js", "kind": "js", "content_marker": "JS_VISIBLE"}]
            # Keep Crawl4AI's independent default robots posture out of this
            # policy assertion; test only Architect's guarded modes here.
            with tempfile.TemporaryDirectory() as td, patch.dict(__import__("os").environ, {"PLAYWRIGHT_BROWSERS_PATH": "/opt/data/.cache/ms-playwright"}), patch.object(matrix, "MODES", matrix.MODES[:2]):
                result = matrix.run_matrix(targets, max_pages=2, depth=1, repetitions=1, output=str(Path(td) / "local.json"))
            self.assertEqual(len(result["runs"]), 4)
            arch = [r for r in result["runs"] if r["mode"].startswith("architect")]
            self.assertFalse(denied, "Architect guard should never request denied path")
            self.assertTrue(all(r["success"] for r in arch), arch)
            by = {(r["target"], r["mode"]): r for r in arch}
            self.assertEqual(by["static", "architect-http"]["metrics"]["pages"], 1)
            self.assertIsNotNone(by["static", "architect-http"]["frontier_warning"])
            self.assertTrue(by["static", "architect-http"]["content_present"])
            self.assertFalse(by["js", "architect-http"]["content_present"])
            self.assertTrue(by["js", "architect-ladder"]["content_present"])
        finally:
            server.shutdown()
            server.server_close()

if __name__ == "__main__":
    unittest.main()
