"""x402 settlement — pay an HTTP 402 and retry.

The web's 2026 crawl contract has three answers: block, allow, charge. This is
the third one. Any other crawler hits a 402 and stops; D0xed Architect settles
it and reads the page.

Wire format matches D0xedDev's own client (`app/lib/x402-client.ts`):

    402 response  ->  base64(JSON) in the PAYMENT-REQUIRED header
    retry request ->  X-PAYMENT        when x402Version == 1
                      PAYMENT-SIGNATURE when x402Version == 2

Payment is EIP-3009 `transferWithAuthorization` on Base (eip155:8453), signed
with EIP-712. Only a signature is produced — no gas, no broadcast. Settlement
is the facilitator's job. That is the whole point of x402: the paying side needs
no ETH.

Transport is stdlib urllib, matching the rest of this package — no `requests`.

Safety: spend is capped. `PayPolicy` refuses any requirement above
`max_per_call`, or that would push a session past `max_total`.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import secrets
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field

from eth_account import Account
from eth_account.messages import encode_typed_data

# ── chain + asset constants ────────────────────────────────────────────────

CHAIN_IDS = {"eip155:8453": 8453, "eip155:84532": 84532}
USDC = {
    "eip155:8453": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
    "eip155:84532": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
}
PREFERRED_NETWORKS = ("eip155:8453", "eip155:84532")
USDC_DECIMALS = 6

# EIP-712 struct for EIP-3009. Field order is load-bearing — the type hash is
# computed from this exact sequence.
TRANSFER_WITH_AUTHORIZATION = [
    {"name": "from", "type": "address"},
    {"name": "to", "type": "address"},
    {"name": "value", "type": "uint256"},
    {"name": "validAfter", "type": "uint256"},
    {"name": "validBefore", "type": "uint256"},
    {"name": "nonce", "type": "bytes32"},
]

# eth_account's encoder wants types as a map of struct name -> field list.
EIP712_TYPES = {"TransferWithAuthorization": TRANSFER_WITH_AUTHORIZATION}


class PaymentRequired(Exception):
    """Raised when a 402 cannot or must not be settled."""


class BudgetExceeded(PaymentRequired):
    """Raised when settling would breach the configured spend cap."""


# ── base64 helpers ─────────────────────────────────────────────────────────

def b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def b64d(text: str) -> bytes:
    return base64.b64decode(text)


# ── transport ──────────────────────────────────────────────────────────────

def _request(method: str, url: str, headers: dict, timeout: int):
    """Return (status, lowercased_headers, body). 4xx/5xx do not raise."""
    req = urllib.request.Request(url, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, {k.lower(): v for k, v in r.headers.items()}, r.read()
    except urllib.error.HTTPError as e:
        body = b""
        try:
            body = e.read()
        except Exception:  # noqa: BLE001 - body may be unreadable
            pass
        return e.code, {k.lower(): v for k, v in (e.headers or {}).items()}, body


# ── challenge parsing ──────────────────────────────────────────────────────

def parse_challenge(headers: dict, body: bytes = b"") -> dict | None:
    """Pull x402 terms out of a 402.

    Accepts the header form (what Cloudflare and D0xedDev emit) and falls back
    to a JSON body, because not every seller puts it in the header.
    """
    lower = {k.lower(): v for k, v in (headers or {}).items()}
    for header in ("payment-required", "x-payment-required", "x-402-payment-required"):
        raw = lower.get(header)
        if not raw:
            continue
        try:
            return json.loads(b64d(raw))
        except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError):
            try:
                return json.loads(raw)
            except json.JSONDecodeError:
                continue

    try:
        parsed = json.loads(body.decode("utf-8", "replace"))
    except (ValueError, AttributeError):
        return None
    if isinstance(parsed, dict) and "accepts" in parsed:
        return parsed
    return None


def amount_of(req: dict) -> int:
    """Atomic-unit price. v1 calls it maxAmountRequired, v2 calls it amount."""
    for key in ("maxAmountRequired", "amount", "max_amount_required"):
        if key in req:
            return int(req[key])
    raise PaymentRequired("payment requirement has no amount field")


def human(req: dict) -> str:
    """Format a requirement price as USDC for logs and reports."""
    return f"{amount_of(req) / 10**USDC_DECIMALS:.6f} USDC"


def select(req: dict, networks=PREFERRED_NETWORKS) -> dict:
    """Pick the cheapest acceptable requirement on a network we can sign for."""
    accepts = req.get("accepts") or []
    usable = [
        r for r in accepts
        if str(r.get("scheme", "exact")) == "exact" and r.get("network") in networks
    ]
    if not usable:
        seen = ", ".join(sorted({str(r.get("network")) for r in accepts})) or "none"
        raise PaymentRequired(
            f"no settleable requirement (offered networks: {seen}; "
            f"supported: {', '.join(networks)})")
    return min(usable, key=amount_of)


# ── payload construction ───────────────────────────────────────────────────

def build_authorization(req: dict, account, valid_for: int = 300) -> dict:
    """Build the EIP-3009 authorization for one requirement."""
    now = int(time.time())
    return {
        "from": account.address,
        "to": req["payTo"],
        "value": str(amount_of(req)),
        "validAfter": str(max(0, now - 60)),
        "validBefore": str(now + valid_for),
        # 32 random bytes — EIP-3009 nonces are single-use by construction.
        "nonce": "0x" + secrets.token_hex(32),
    }


def sign_authorization(req: dict, account, authorization: dict) -> str:
    """EIP-712 sign the authorization against the token's own domain."""
    network = req["network"]
    chain_id = CHAIN_IDS.get(network)
    if chain_id is None:
        raise PaymentRequired(f"unknown chain for network {network!r}")

    asset = req.get("asset") or USDC.get(network)
    extra = req.get("extra") or {}
    # name/version come from the seller's `extra`, or from USDC's known values.
    domain = {
        "name": extra.get("name") or "USD Coin",
        "version": str(extra.get("version") or "2"),
        "chainId": chain_id,
        "verifyingContract": asset,
    }
    signed = Account.sign_typed_data(
        account.key, domain, EIP712_TYPES, authorization)
    signature = signed.signature
    if isinstance(signature, bytes):
        signature = signature.hex()
    if not signature.startswith("0x"):
        signature = "0x" + signature
    return signature


def build_payload(req: dict, x402_version: int, account,
                  resource: str | None = None) -> dict:
    """Assemble the full payload the seller expects in the retry header."""
    auth = build_authorization(req, account)
    signature = sign_authorization(req, account, auth)

    payload = {
        "x402Version": x402_version,
        "scheme": req.get("scheme", "exact"),
        "network": req["network"],
        "payload": {"signature": signature, "authorization": auth},
    }
    if x402_version == 2:
        payload["resource"] = resource
        payload["accepted"] = req
    return payload


def payment_header(payload: dict) -> dict[str, str]:
    """v2 -> PAYMENT-SIGNATURE, v1 -> X-PAYMENT. Mirrors the TS client exactly."""
    encoded = b64e(json.dumps(payload, separators=(",", ":")).encode())
    name = "PAYMENT-SIGNATURE" if payload.get("x402Version") == 2 else "X-PAYMENT"
    return {name: encoded}


# ── spend policy ───────────────────────────────────────────────────────────

@dataclass
class PayPolicy:
    """Hard caps on what a session is allowed to spend.

    `enabled=False` is the default everywhere: a crawler should never spend
    money because someone forgot a flag.
    """
    enabled: bool = False
    max_per_call: int = 0
    max_total: int = 0
    spent: int = 0
    receipts: list = field(default_factory=list)

    def check(self, req: dict) -> int:
        if not self.enabled:
            raise PaymentRequired("payment disabled — pass --pay to settle 402s")
        price = amount_of(req)
        if price > self.max_per_call:
            raise BudgetExceeded(
                f"{human(req)} exceeds --max-per-call "
                f"({self.max_per_call / 10**USDC_DECIMALS:.6f} USDC)")
        if self.spent + price > self.max_total:
            raise BudgetExceeded(
                f"{human(req)} would push session spend to "
                f"{(self.spent + price) / 10**USDC_DECIMALS:.6f} USDC, "
                f"over --max-spend ({self.max_total / 10**USDC_DECIMALS:.6f} USDC)")
        return price

    def record(self, url: str, req: dict, price: int) -> None:
        self.spent += price
        self.receipts.append({
            "url": url,
            "network": req["network"],
            "payTo": req["payTo"],
            "amount": price,
            "amount_usdc": price / 10**USDC_DECIMALS,
            "at": int(time.time()),
        })

    def summary(self) -> dict:
        return {
            "enabled": self.enabled,
            "spent_atomic": self.spent,
            "spent_usdc": self.spent / 10**USDC_DECIMALS,
            "max_total_usdc": self.max_total / 10**USDC_DECIMALS,
            "receipts": self.receipts,
        }


# ── the client ─────────────────────────────────────────────────────────────

def load_account(key_path: str | None = None, private_key: str | None = None):
    """Load the paying account.

    Order: explicit key argument, then $D0XED_PAY_KEY, then the key file. The
    key is never logged or written anywhere.
    """
    if private_key:
        return Account.from_key(private_key)
    env = os.environ.get("D0XED_PAY_KEY")
    if env:
        return Account.from_key(env)
    path = key_path or os.environ.get("D0XED_PAY_KEY_FILE")
    if path and os.path.exists(path):
        with open(path, "r", encoding="utf-8") as fh:
            return Account.from_key(fh.read().strip())
    raise PaymentRequired(
        "no paying key: pass --key-file, set D0XED_PAY_KEY, or set D0XED_PAY_KEY_FILE")


def fetch_paid(url: str, policy: PayPolicy, account=None, *,
               method: str = "GET", timeout: int = 30,
               headers: dict | None = None) -> dict:
    """GET a URL, settling a 402 if the policy allows it.

    Returns a dict: status, paid, amount_usdc, receipt, content, headers.
    Raises PaymentRequired for any refusal and lets other HTTP errors stand.
    """
    base_headers = dict(headers or {})

    status, resp_headers, content = _request(method, url, base_headers, timeout)

    if status != 402:
        return {"status": status, "paid": False, "amount_usdc": 0.0,
                "content": content, "headers": resp_headers, "receipt": None}

    challenge = parse_challenge(resp_headers, content)
    if challenge is None:
        raise PaymentRequired(
            f"{url} returned 402 with no parseable PAYMENT-REQUIRED terms")

    version = int(challenge.get("x402Version", 1))
    requirement = select(challenge)
    price = policy.check(requirement)

    if account is None:
        account = load_account()

    payload = build_payload(requirement, version, account,
                            resource=challenge.get("resource") or url)
    retry_headers = {**base_headers, **payment_header(payload)}
    retry_headers.setdefault("Accept", "application/json")

    status2, headers2, content2 = _request(method, url, retry_headers, timeout)

    if status2 in (200, 201, 202):
        policy.record(url, requirement, price)
        return {
            "status": status2,
            "paid": True,
            "amount_usdc": price / 10**USDC_DECIMALS,
            "content": content2,
            "headers": headers2,
            "receipt": policy.receipts[-1],
        }

    raise PaymentRequired(
        f"{url}: paid {human(requirement)} but seller answered "
        f"{status2} — no receipt recorded")