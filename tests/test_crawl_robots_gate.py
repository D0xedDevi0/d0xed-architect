"""Robots deny rules must prevent page requests, including queued llms links."""
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import patch

from architect import cli, http, mcp_server

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("architect_bench_runner", ROOT / "bench" / "tool_architect.py")
assert spec is not None and spec.loader is not None
bench = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bench)

BASE = "https://example.org"
DENIED = BASE + "/private"
ALLOWED = BASE + "/public"


def policies():
    return http.parse_robots("User-agent: *\nDisallow: /private\n")


def llms():
    return http.LlmsTxt(url=BASE + "/llms.txt", found=True,
                        sections={"links": [("private", DENIED, ""), ("public", ALLOWED, "")]})


class CrawlRobotsGateTests(TestCase):
    def test_cli_does_not_fetch_denied_start_or_queued_link(self):
        args = SimpleNamespace(url=DENIED, signature_agent=None, pay=False,
                               graph=None, depth=0, max_pages=4, concurrency=2,
                               timeout=2, out=None, json=False)
        with patch.object(cli._http, "load_robots", return_value=policies()), \
             patch.object(cli._http, "load_llms_txt", return_value=llms()), \
             patch.object(cli, "_fetch_one", return_value=(404, None)) as fetch, \
             patch.object(cli, "_emit"):
            cli.cmd_crawl(args)
        self.assertEqual([c.args[0] for c in fetch.call_args_list], [ALLOWED])

    def test_mcp_does_not_fetch_denied_start_or_queued_link(self):
        with patch.object(mcp_server._http, "load_robots", return_value=policies()), \
             patch.object(mcp_server._http, "load_llms_txt", return_value=llms()), \
             patch.object(mcp_server._http, "fetch", return_value=SimpleNamespace(status=404)) as fetch:
            result = json.loads(mcp_server.map_site(DENIED, max_pages=4, depth=0))
        self.assertEqual([c.args[0] for c in fetch.call_args_list], [ALLOWED])
        self.assertEqual(result["pages_crawled"], 0)

    def test_bench_does_not_fetch_or_render_denied_start_or_queued_link(self):
        with patch.object(bench._http, "load_robots", return_value=policies()), \
             patch.object(bench._http, "load_llms_txt", return_value=llms()), \
             patch.object(bench._http, "fetch", return_value=SimpleNamespace(status=404)) as fetch, \
             patch.object(bench._esc, "render") as render:
            result = bench.run(DENIED, 4, 0)
        self.assertEqual([c.args[0] for c in fetch.call_args_list], [ALLOWED])
        render.assert_not_called()
        self.assertEqual(result["pages"], 0)
