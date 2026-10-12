"""Robots deny rules must prevent page requests, including queued llms links."""
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import patch

from architect import cli, escalate, http, mcp_server

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
        with patch.object(cli._http, "load_robots", return_value=policies()) as load, \
             patch.object(cli._http, "load_llms_txt", return_value=llms()), \
             patch.object(cli, "_fetch_one", return_value=(404, None)) as fetch, \
             patch.object(cli, "_emit"):
            cli.cmd_crawl(args)
        self.assertTrue(load.call_args.kwargs["strict"])
        self.assertEqual([c.args[0] for c in fetch.call_args_list], [ALLOWED])

    def test_mcp_does_not_fetch_denied_start_or_queued_link(self):
        with patch.object(mcp_server._http, "load_robots", return_value=policies()) as load, \
             patch.object(mcp_server._http, "load_llms_txt", return_value=llms()), \
             patch.object(mcp_server._http, "fetch", return_value=SimpleNamespace(status=404)) as fetch:
            result = json.loads(mcp_server.map_site(DENIED, max_pages=4, depth=0))
        self.assertTrue(load.call_args.kwargs["strict"])
        self.assertEqual([c.args[0] for c in fetch.call_args_list], [ALLOWED])
        self.assertEqual(result["pages_crawled"], 0)

    def test_bench_does_not_fetch_or_render_denied_start_or_queued_link(self):
        with patch.object(bench._http, "load_robots", return_value=policies()) as load, \
             patch.object(bench._http, "load_llms_txt", return_value=llms()), \
             patch.object(bench._http, "fetch", return_value=SimpleNamespace(status=404)) as fetch, \
             patch.object(bench._esc, "render") as render:
            result = bench.run(DENIED, 4, 0)
        self.assertTrue(load.call_args.kwargs["strict"])
        self.assertEqual([c.args[0] for c in fetch.call_args_list], [ALLOWED])
        render.assert_not_called()
        self.assertEqual(result["pages"], 0)

    def test_cli_http_fetch_receives_redirect_guard(self):
        args = SimpleNamespace(timeout=2, signature_agent=None, _policy=None)
        with patch.object(cli._http, "fetch", return_value=SimpleNamespace(
                status=404, content_type="application/json")) as fetch:
            cli._fetch_one(ALLOWED, args, self._access())
        fetch.call_args.kwargs["redirect_guard"](ALLOWED)
        with self.assertRaises(http.FetchError):
            fetch.call_args.kwargs["redirect_guard"](DENIED)

    def test_cli_paid_fetch_receives_redirect_guard(self):
        args = SimpleNamespace(timeout=2, signature_agent=None,
                               _policy=SimpleNamespace(enabled=True), _account=None)
        with patch.object(cli._x402, "fetch_paid", return_value={
                "paid": False, "status": 404, "content": b""}) as paid:
            cli._fetch_one(ALLOWED, args, self._access())
        guard = paid.call_args.kwargs["redirect_guard"]
        with self.assertRaises(http.FetchError):
            guard(DENIED)

    def test_mcp_http_fetch_receives_redirect_guard(self):
        with patch.object(mcp_server._http, "load_robots", return_value=policies()), \
             patch.object(mcp_server._http, "load_llms_txt", return_value=llms()), \
             patch.object(mcp_server._http, "fetch", return_value=SimpleNamespace(status=404)) as fetch:
            mcp_server.map_site(ALLOWED, max_pages=4, depth=0)
        guard = fetch.call_args.kwargs["redirect_guard"]
        with self.assertRaises(http.FetchError):
            guard(DENIED)

    def test_bench_http_and_browser_receive_guards(self):
        shell = http.Response(url=ALLOWED, status=200, headers={},
                              body=b'<html><div id="root"></div></html>', content_type="text/html")
        with patch.object(bench._http, "load_robots", return_value=policies()), \
             patch.object(bench._http, "load_llms_txt", return_value=http.LlmsTxt(url=BASE+"/llms.txt")), \
             patch.object(bench._http, "fetch", return_value=shell) as fetch, \
             patch.object(bench._esc, "looks_js_dependent", return_value=SimpleNamespace(
                 needs_render=True, reasons=["shell"])), \
             patch.object(bench._esc, "render", return_value=shell) as render, \
             patch.object(bench, "LADDER", True), \
             patch.object(bench, "BUDGET", SimpleNamespace(spend=lambda: True)):
            bench.run(ALLOWED, 1, 0)
        for guard in (fetch.call_args.kwargs["redirect_guard"],
                      render.call_args.kwargs["request_guard"]):
            with self.assertRaises(http.FetchError):
                guard(DENIED)

    def test_fetch_smart_threads_redirect_and_request_guards(self):
        shell = http.Response(url=ALLOWED, status=200, headers={},
                              body=b'<html><div id="root"></div></html>', content_type="text/html")
        with patch.object(http, "fetch", return_value=shell) as fetch, \
             patch.object(escalate, "looks_js_dependent", return_value=SimpleNamespace(
                 needs_render=True, reasons=["shell"])), \
             patch.object(escalate, "render", return_value=shell) as render:
            escalate.fetch_smart(ALLOWED, redirect_guard=self._access().require,
                                 request_guard=self._access().require)
        for kw, name in ((fetch.call_args.kwargs["redirect_guard"], "redirect_guard"),
                         (render.call_args.kwargs["request_guard"], "request_guard")):
            kw(ALLOWED)
            with self.assertRaises(http.FetchError, msg=name):
                kw(DENIED)

    def test_cli_render_armed_escalates_shell_with_guard(self):
        shell = http.Response(url=ALLOWED, status=200, headers={},
                              body=b'<html><div id="root"></div></html>', content_type="text/html")
        rendered = http.Response(url=ALLOWED, status=200, headers={},
                                 body=b'<h1>Rendered by JS</h1>', content_type="text/html")
        rendered.rendered = True
        args = SimpleNamespace(timeout=2, signature_agent=None, _policy=None,
                               _budget=escalate.EscalationBudget(max_renders=2))
        with patch.object(cli._http, "fetch", return_value=shell), \
             patch.object(cli._esc, "looks_js_dependent", return_value=SimpleNamespace(
                 needs_render=True, reasons=["shell"])), \
             patch.object(cli._esc, "render", return_value=rendered) as render:
            status, text = cli._fetch_one(ALLOWED, args, self._access())
        self.assertEqual(status, 200)
        self.assertIn("Rendered by JS", text)
        render.assert_called_once()
        render.call_args.kwargs["request_guard"](ALLOWED)
        with self.assertRaises(http.FetchError):
            render.call_args.kwargs["request_guard"](DENIED)

    def test_cli_default_never_renders(self):
        shell = http.Response(url=ALLOWED, status=200, headers={},
                              body=b'<html><div id="root"></div></html>', content_type="text/html")
        args = SimpleNamespace(timeout=2, signature_agent=None, _policy=None,
                               _budget=None)
        with patch.object(cli._http, "fetch", return_value=shell), \
             patch.object(cli._esc, "render") as render:
            status, text = cli._fetch_one(ALLOWED, args, self._access())
        self.assertEqual(status, 200)
        self.assertIn("root", text)
        render.assert_not_called()

    def test_mcp_render_true_escalates_and_reports(self):
        shell = http.Response(url=ALLOWED, status=200, headers={},
                              body=b'<html><div id="root"></div></html>', content_type="text/html")
        rendered = http.Response(url=ALLOWED, status=200, headers={},
                                 body=b'<h1>Rendered by JS</h1>', content_type="text/html")
        rendered.rendered = True
        with patch.object(mcp_server._http, "load_robots", return_value=policies()), \
             patch.object(mcp_server._http, "load_llms_txt", return_value=http.LlmsTxt(url=BASE + "/llms.txt")), \
             patch.object(mcp_server._http, "fetch", return_value=shell), \
             patch.object(mcp_server._esc, "looks_js_dependent", return_value=SimpleNamespace(
                 needs_render=True, reasons=["shell"])), \
             patch.object(mcp_server._esc, "render", return_value=rendered) as render:
            result = json.loads(mcp_server.map_site(ALLOWED, max_pages=1, depth=0,
                                                    render=True))
        self.assertEqual(result["rendered"], 1)
        render.assert_called_once()
        with self.assertRaises(http.FetchError):
            render.call_args.kwargs["request_guard"](DENIED)

    def test_mcp_default_never_renders(self):
        shell = http.Response(url=ALLOWED, status=200, headers={},
                              body=b'<html><div id="root"></div></html>', content_type="text/html")
        with patch.object(mcp_server._http, "load_robots", return_value=policies()), \
             patch.object(mcp_server._http, "load_llms_txt", return_value=http.LlmsTxt(url=BASE + "/llms.txt")), \
             patch.object(mcp_server._http, "fetch", return_value=shell), \
             patch.object(mcp_server._esc, "render") as render:
            result = json.loads(mcp_server.map_site(ALLOWED, max_pages=1, depth=0))
        self.assertEqual("rendered" not in result, True)
        render.assert_not_called()

    @staticmethod
    def _access():
        from architect.crawl_access import CrawlAccess
        return CrawlAccess(BASE, policies())
