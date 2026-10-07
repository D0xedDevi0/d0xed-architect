"""End-to-end x402 test: a mock seller that cryptographically verifies payment.

The seller recovers the EIP-712 signer from the EIP-3009 authorization we send.
If our signing were wrong in any way — domain, field order, type hash — recovery
would yield a different address and the sale would be refused. So a passing
test means the payment payload is genuinely valid, not merely well-formed.

No money moves. Nothing is broadcast. Settlement is the facilitator's job.
"""

import json
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, "/opt/data/d0xed-architect")

from eth_account import Account
from eth_account.messages import encode_typed_data

from architect import x402

PAY_TO = "0x112fd9bb2f09777cfcadefed92b3935568f20ba3"
ASSET = x402.USDC["eip155:8453"]
PRICE = "10000"  # 0.01 USDC

# Throwaway key. Never the real agent wallet — no funds are at risk here.
PAYER = Account.from_key("0x" + "11" * 32)

SEEN_NONCES: set[str] = set()
STATE = {"version": 1, "price": PRICE, "sold": 0}


def challenge(version: int) -> dict:
    req = {
        "scheme": "exact",
        "network": "eip155:8453",
        "payTo": PAY_TO,
        "maxTimeoutSeconds": 300,
        "asset": ASSET,
        "extra": {"name": "USD Coin", "version": "2"},
        "description": "D0xed Architect premium intel",
    }
    if version == 1:
        req["maxAmountRequired"] = STATE["price"]
        req["resource"] = "/paid/intel"
        req["mimeType"] = "application/json"
    else:
        req["amount"] = STATE["price"]
    return {"x402Version": version, "accepts": [req], "resource": "/paid/intel"}


class Seller(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path.startswith("/free"):
            body = b'{"free":true}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        version = STATE["version"]
        header = self.headers.get("PAYMENT-SIGNATURE") or self.headers.get("X-PAYMENT")

        if not header:
            body = json.dumps(challenge(version)).encode()
            self.send_response(402)
            self.send_header(
                "PAYMENT-REQUIRED",
                x402.b64e(body))
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        try:
            payload = json.loads(x402.b64d(header))
            auth = payload["payload"]["authorization"]
            sig = payload["payload"]["signature"]

            domain = {"name": "USD Coin", "version": "2", "chainId": 8453,
                      "verifyingContract": ASSET}
            recovered = Account.recover_message(
                encode_typed_data(domain, x402.EIP712_TYPES, auth),
                signature=sig)

            problems = []
            if recovered != auth["from"]:
                problems.append(f"signature recovers to {recovered}, not {auth['from']}")
            if auth["to"].lower() != PAY_TO.lower():
                problems.append("payTo mismatch")
            if int(auth["value"]) != int(STATE["price"]):
                problems.append("value mismatch")
            if int(auth["validBefore"]) < time.time():
                problems.append("authorization expired")
            if auth["nonce"] in SEEN_NONCES:
                problems.append("nonce replayed")
            if problems:
                raise ValueError("; ".join(problems))

            SEEN_NONCES.add(auth["nonce"])
            STATE["sold"] += 1
            body = json.dumps({
                "premium": True,
                "from": recovered,
                "paid": auth["value"],
                "version": payload["x402Version"],
            }).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except Exception as exc:  # noqa: BLE001 - test surface
            body = json.dumps({"error": str(exc)}).encode()
            self.send_response(402)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)


def main() -> int:
    server = HTTPServer(("127.0.0.1", 0), Seller)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{port}/paid/intel"

    failures = []
    stats = {"n": 0}

    def check(name, cond, extra=""):
        stats["n"] += 1
        print(f"  {'PASS' if cond else 'FAIL'}  {name}{f' — {extra}' if extra else ''}")
        if not cond:
            failures.append(name)

    print("═══ x402 SETTLEMENT ACCEPTANCE ═══")

    # --- 1. payment disabled (default) must refuse, and must not sign
    pol = x402.PayPolicy(enabled=False)
    try:
        x402.fetch_paid(url, pol, account=PAYER)
        check("payment disabled refuses 402", False, "it did not raise")
    except x402.PaymentRequired:
        check("payment disabled refuses 402", True)
    check("nothing spent while disabled", pol.spent == 0)

    # --- 2. happy path, v1 / X-PAYMENT
    STATE["version"] = 1
    pol = x402.PayPolicy(enabled=True, max_per_call=50_000, max_total=100_000)
    res = x402.fetch_paid(url, pol, account=PAYER)
    data = json.loads(res["content"])
    check("v1 clears the 402", res["status"] == 200 and res["paid"])
    check("v1 signature recovered by seller", data.get("from", "").lower() == PAYER.address.lower())
    check("v1 charged 0.01 USDC", abs(res["amount_usdc"] - 0.01) < 1e-9, f"{res['amount_usdc']:.6f}")
    check("v1 receipt recorded", len(pol.receipts) == 1 and pol.spent == 10_000)

    # --- 3. happy path, v2 / PAYMENT-SIGNATURE
    STATE["version"] = 2
    pol2 = x402.PayPolicy(enabled=True, max_per_call=50_000, max_total=100_000)
    res2 = x402.fetch_paid(url, pol2, account=PAYER)
    check("v2 clears the 402 (PAYMENT-SIGNATURE)", res2["status"] == 200 and res2["paid"])

    # --- 4. per-call cap
    pol3 = x402.PayPolicy(enabled=True, max_per_call=5_000, max_total=100_000)
    try:
        x402.fetch_paid(url, pol3, account=PAYER)
        check("per-call cap blocks oversize price", False, "it did not raise")
    except x402.BudgetExceeded:
        check("per-call cap blocks oversize price", True)

    # --- 5. session cap: first charge is fine, the second must breach
    pol4 = x402.PayPolicy(enabled=True, max_per_call=50_000, max_total=15_000)
    x402.fetch_paid(url, pol4, account=PAYER)  # 10_000 — inside the 15_000 cap
    try:
        x402.fetch_paid(url, pol4, account=PAYER)  # 20_000 — must be refused
        check("session cap blocks breach", False, "it did not raise")
    except x402.BudgetExceeded:
        check("session cap blocks breach", True)
    check("spend frozen at the allowed amount", pol4.spent == 10_000,
          f"{pol4.spent / 10**6:.6f} USDC")

    # --- 6. nonces must be unique across calls
    pol5 = x402.PayPolicy(enabled=True, max_per_call=50_000, max_total=100_000)
    x402.fetch_paid(url, pol5, account=PAYER)
    x402.fetch_paid(url, pol5, account=PAYER)
    check("every call mints a fresh nonce", len(SEEN_NONCES) == len(set(SEEN_NONCES))
          and len(SEEN_NONCES) >= 4, f"{len(SEEN_NONCES)} distinct")

    # --- 7. free endpoints must not trigger payment
    pol6 = x402.PayPolicy(enabled=True, max_per_call=50_000, max_total=100_000)
    free = x402.fetch_paid(f"http://127.0.0.1:{port}/free", pol6, account=PAYER)
    check("no 402 means nothing is spent",
          free["status"] == 200 and not free["paid"] and pol6.spent == 0)

    server.shutdown()
    print()
    if failures:
        print(f"❌ {len(failures)} FAILED: {', '.join(failures)}")
        return 1
    print(f"✅ all {stats['n']} checks passed — {STATE['sold']} verified settlements, "
          f"0 broadcast, 0 spent")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())