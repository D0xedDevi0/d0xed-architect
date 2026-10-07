"""End-to-end: does the CRAWLER actually pay a 402 and keep going?

Stands up a local site where /premium is x402-gated, then runs the real CLI
against it with --pay. Proves the whole loop: discover -> 402 -> sign ->
settle -> treat the paid page as a normal page.

Evidence is read from the SQLite graph, which stores each page's extracted
title. That proves the paid body was actually fetched and parsed — not merely
that a receipt got printed.

Also dogfoods our own robots.txt/llms.txt parser against the files written for
d0xeddev.com — if those files are malformed, we find out here.
"""

import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, "/opt/data/d0xed-architect")

from eth_account import Account
from eth_account.messages import encode_typed_data

from architect import http as ahttp
from architect import x402

ASSET = x402.USDC["eip155:8453"]
PAYER = Account.from_key("0x" + "22" * 32)
PAY_TO = "0x112fd9bb2f09777cfcadefed92b3935568f20ba3"
REPO = "/opt/data/d0xed-architect"
PRICE = "20000"  # 0.02 USDC

HOME = b"""<html><head><title>Mock Site</title></head><body>
<h1>Home</h1>
<a href="/free">free page</a>
<a href="/premium">premium page</a>
</body></html>"""

FREE = b"""<html><head><title>Free Page</title></head><body>
<h1>Free</h1><p>This page costs nothing.</p>
<a href="/">home</a></body></html>"""

PREMIUM = b"""<html><head><title>Premium Intel</title></head><body>
<h1>Premium</h1><p>PAID_SENTINEL this content sat behind an x402 gate.</p>
</body></html>"""

PAID_NONCES: list = []


class Site(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="text/html", extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/robots.txt":
            return self._send(200, b"User-agent: *\nAllow: /\n", "text/plain")

        if self.path == "/premium":
            header = (self.headers.get("PAYMENT-SIGNATURE")
                      or self.headers.get("X-PAYMENT"))
            if not header:
                challenge = {
                    "x402Version": 1,
                    "accepts": [{
                        "scheme": "exact",
                        "network": "eip155:8453",
                        "maxAmountRequired": PRICE,
                        "payTo": PAY_TO,
                        "asset": ASSET,
                        "resource": "/premium",
                        "description": "premium intel",
                        "mimeType": "text/html",
                        "maxTimeoutSeconds": 300,
                        "extra": {"name": "USD Coin", "version": "2"},
                    }],
                    "resource": "/premium",
                }
                body = json.dumps(challenge).encode()
                return self._send(402, body, "application/json",
                                  {"PAYMENT-REQUIRED": x402.b64e(body)})
            try:
                payload = json.loads(x402.b64d(header))
                auth = payload["payload"]["authorization"]
                domain = {"name": "USD Coin", "version": "2", "chainId": 8453,
                          "verifyingContract": ASSET}
                got = Account.recover_message(
                    encode_typed_data(domain, x402.EIP712_TYPES, auth),
                    signature=payload["payload"]["signature"])
                if got.lower() != auth["from"].lower():
                    raise ValueError("signature recovered to another address")
                if int(auth["value"]) != int(PRICE):
                    raise ValueError("wrong amount")
                if int(auth["validBefore"]) < time.time():
                    raise ValueError("expired")
                if auth["nonce"] in PAID_NONCES:
                    raise ValueError("nonce replayed")
                PAID_NONCES.append(auth["nonce"])
                return self._send(200, PREMIUM)
            except Exception as exc:  # noqa: BLE001 - test surface
                return self._send(402, json.dumps({"error": str(exc)}).encode(),
                                  "application/json")

        if self.path == "/free":
            return self._send(200, FREE)
        return self._send(200, HOME)


def page_labels(dbpath: str) -> set:
    """Titles of every page the crawler actually parsed into the graph."""
    if not os.path.exists(dbpath):
        return set()
    con = sqlite3.connect(dbpath)
    try:
        rows = con.execute(
            "SELECT label FROM nodes WHERE kind = 'page'").fetchall()
    finally:
        con.close()
    return {r[0] for r in rows if r[0]}


def run_cli(base, out, graph, extra):
    return subprocess.run(
        [sys.executable, "-m", "architect.cli", "crawl", base,
         "--depth", "2", "--max-pages", "10", "--out", out, "--graph", graph]
        + extra,
        capture_output=True, text=True, cwd=REPO,
        env={**os.environ, "PYTHONPATH": REPO}, timeout=180)


def main() -> int:
    failures = []
    stats = {"n": 0}

    def check(name, cond, extra=""):
        stats["n"] += 1
        print(f"  {'PASS' if cond else 'FAIL'}  {name}{f' — {extra}' if extra else ''}")
        if not cond:
            failures.append(name)

    server = HTTPServer(("127.0.0.1", 0), Site)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{port}"

    tmp = tempfile.mkdtemp()
    keyfile = os.path.join(tmp, "pay.key")
    with open(keyfile, "w") as fh:
        fh.write(PAYER.key.hex())
    os.chmod(keyfile, 0o600)
    out = os.path.join(tmp, "site.md")

    print("═══ CRAWLER PAYS A 402 — END TO END ═══")

    # --- 1. WITHOUT --pay: the gate stops the crawler at that page
    PAID_NONCES.clear()
    g1 = os.path.join(tmp, "g1.db")
    r = run_cli(base, out, g1, [])
    labels1 = page_labels(g1)
    check("no --pay: exit 0", r.returncode == 0, f"rc={r.returncode}")
    check("no --pay: free page crawled", "Free Page" in labels1, str(sorted(labels1)))
    check("no --pay: gated page NOT crawled", "Premium Intel" not in labels1)
    check("no --pay: nothing settled", len(PAID_NONCES) == 0)
    check("no --pay: 402 gate surfaced in the report", "402" in open(out).read())

    # --- 2. WITH --pay: the gate is cleared and the paid page is parsed
    PAID_NONCES.clear()
    g2 = os.path.join(tmp, "g2.db")
    r = run_cli(base, out, g2, ["--pay", "--max-spend", "0.25",
                                "--max-per-call", "0.05", "--key-file", keyfile])
    labels2 = page_labels(g2)
    check("--pay: exit 0", r.returncode == 0, f"rc={r.returncode}")
    check("--pay: seller cryptographically verified our signature",
          len(PAID_NONCES) == 1, f"{len(PAID_NONCES)} settlement(s)")
    check("--pay: PAID page now crawled", "Premium Intel" in labels2,
          str(sorted(labels2)))
    check("--pay: free page still crawled", "Free Page" in labels2)
    check("--pay: receipt logged at the right price",
          "paid 0.020000 USDC" in r.stderr)
    check("--pay: agent declares the settlement",
          "settled 1 paywall" in r.stderr)

    # --- 3. budget refusal: a cap below the price must not settle
    PAID_NONCES.clear()
    g3 = os.path.join(tmp, "g3.db")
    run_cli(base, out, g3, ["--pay", "--max-spend", "0.25",
                            "--max-per-call", "0.001", "--key-file", keyfile])
    check("--max-per-call refuses an over-cap price", len(PAID_NONCES) == 0)
    check("over-cap price keeps the page out of the graph",
          "Premium Intel" not in page_labels(g3))

    # --- 4. dogfood our own robots.txt / llms.txt
    rb = open("/opt/data/D0XEDDEV/public/robots.txt").read()
    parsed = ahttp.parse_robots(rb)
    check("robots.txt: found + parses", parsed.found)
    check("robots.txt: content-signals parsed",
          parsed.signals.get("ai-train") == "yes", str(parsed.signals))
    check("robots.txt: /admin disallowed", not parsed.can_fetch("/admin"))
    check("robots.txt: /api allowed", parsed.can_fetch("/api/agents"))
    check("robots.txt: sitemap advertised",
          any("sitemap.xml" in s for s in parsed.sitemaps))

    raw = open("/opt/data/D0XEDDEV/public/llms.txt").read()
    links = len([l for l in raw.splitlines() if l.strip().startswith("- [")])
    check("llms.txt: titled", raw.startswith("# D0xedDev"))
    check("llms.txt: summary blockquote present", "\n> " in raw)
    check("llms.txt: sections >= 5", raw.count("\n## ") >= 5,
          f"{raw.count(chr(10) + '## ')} sections")
    check("llms.txt: >= 40 link entries", links >= 40, f"{links} links")

    server.shutdown()
    print()
    if failures:
        print(f"❌ {len(failures)} FAILED: {', '.join(failures)}")
        return 1
    print(f"✅ all {stats['n']} checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())