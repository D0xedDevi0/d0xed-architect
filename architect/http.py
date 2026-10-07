"""Polite, identity-declared fetching layer.

Implements the 2026 crawling contract instead of ignoring it:
  * robots.txt        -> access rules (we honour them by default)
  * content-signals   -> use policy (search / ai-input / ai-train)
  * llms.txt (v2)     -> navigation; fetched before anything else
  * Web Bot Auth      -> Ed25519-signed identity headers (RFC 9421 style)
  * HTTP 402          -> pay-per-crawl / x402 gate -> PayRequired
"""
from __future__ import annotations

import base64
import gzip
import json
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

UA = ("D0xedArchitect/0.1 (+https://d0xeddev.com/architect; "
      "class=search-index; contact=@D0xedDevi0)")
DEFAULT_TIMEOUT = 20
MAX_BYTES = 4_000_000

# AI crawler classes (CrawlForge 2026 taxonomy) — we declare ours honestly.
CRAWLER_CLASS = "search-index"
CONTENT_SIGNAL_USE = "search"


class FetchError(Exception):
    pass


class PayRequired(Exception):
    """Server returned HTTP 402 — a pay-per-crawl / x402 gate."""

    def __init__(self, url: str, price: str | None = None,
                 headers: dict | None = None, body: bytes = b""):
        self.url = url
        self.price = price
        self.headers = headers or {}
        self.body = body
        super().__init__(f"402 payment required: {url} (price={price})")


@dataclass
class Response:
    url: str
    status: int
    headers: dict
    body: bytes
    content_type: str = ""
    elapsed_ms: int = 0
    redirect_chain: list = field(default_factory=list)
    # Set by architect.escalate when a browser was used, so reports can state
    # how many pages genuinely needed rendering.
    rendered: bool = False
    escalation_reason: str = ""

    @property
    def text(self) -> str:
        enc = "utf-8"
        m = re.search(r"charset=([\w.-]+)", self.content_type or "")
        if m:
            enc = m.group(1)
        try:
            return self.body.decode(enc, "replace")
        except Exception:
            return self.body.decode("utf-8", "replace")


def _ssl_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


def _identity_headers(agent_id: str | None = None) -> dict:
    """Web Bot Auth style declaration. Ed25519 signing lands in v0.2."""
    h = {
        "User-Agent": UA,
        "Accept": "text/markdown, text/html;q=0.9, application/json;q=0.8, */*;q=0.5",
        "Accept-Encoding": "gzip",
        "D0xed-Crawler-Class": CRAWLER_CLASS,
        "D0xed-Content-Signal": CONTENT_SIGNAL_USE,
    }
    if agent_id:
        h["Signature-Agent"] = agent_id
    return h


def fetch(url: str, timeout: int = DEFAULT_TIMEOUT, agent_id: str | None = None,
          allow_402: bool = True) -> Response:
    req = urllib.request.Request(url, headers=_identity_headers(agent_id))
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_ssl_ctx()) as r:
            raw = r.read(MAX_BYTES + 1)[:MAX_BYTES]
            if (r.headers.get("Content-Encoding") or "").lower() == "gzip":
                try:
                    raw = gzip.decompress(raw)
                except Exception:
                    pass
            return Response(
                url=r.geturl(), status=r.status,
                headers={k.lower(): v for k, v in r.headers.items()},
                body=raw, content_type=r.headers.get("Content-Type", ""),
                elapsed_ms=int((time.time() - t0) * 1000),
            )
    except urllib.error.HTTPError as e:
        body = b""
        try:
            body = e.read(MAX_BYTES)[:MAX_BYTES]
        except Exception:
            pass
        hdrs = {k.lower(): v for k, v in (e.headers or {}).items()}
        if e.code == 402:
            price = (hdrs.get("x-price") or hdrs.get("x-payment-amount")
                     or hdrs.get("price") or _parse_price_from_body(body))
            if allow_402:
                raise PayRequired(url, price=price, headers=hdrs, body=body) from None
        return Response(url=url, status=e.code, headers=hdrs, body=body,
                        content_type=hdrs.get("content-type", ""),
                        elapsed_ms=int((time.time() - t0) * 1000))
    except Exception as e:
        raise FetchError(f"{url}: {e}") from e


def _parse_price_from_body(body: bytes) -> str | None:
    try:
        j = json.loads(body.decode("utf-8", "replace"))
    except Exception:
        return None
    for k in ("price", "amount", "maxAmountRequired", "cost"):
        if k in j:
            return str(j[k])
    return None


# ---------------------------------------------------------------- robots.txt

@dataclass
class Robots:
    allow: list = field(default_factory=list)
    disallow: list = field(default_factory=list)
    signals: dict = field(default_factory=dict)
    sitemaps: list = field(default_factory=list)
    raw: str = ""
    found: bool = False

    def can_fetch(self, path: str) -> bool:
        best = None
        for rule in self.disallow:
            if rule and path.startswith(rule):
                if best is None or len(rule) > len(best):
                    best = rule
        for rule in self.allow:
            if rule and path.startswith(rule):
                if best is None or len(rule) > len(best):
                    return True
        return best is None


def parse_robots(text: str) -> Robots:
    r = Robots(raw=text, found=True)
    group_is_star = False
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        key, _, val = line.partition(":")
        key, val = key.strip().lower(), val.strip()
        if key == "user-agent":
            group_is_star = val == "*"
        elif group_is_star and key == "disallow" and val:
            r.disallow.append(val)
        elif group_is_star and key == "allow" and val:
            r.allow.append(val)
        elif key == "content-signal":
            for part in val.split(","):
                if "=" in part:
                    k, v = part.split("=", 1)
                    r.signals[k.strip().lower()] = v.strip().lower()
        elif key == "sitemap":
            r.sitemaps.append(val)
    return r


def load_robots(base: str, agent_id: str | None = None) -> Robots:
    url = urllib.parse.urljoin(base, "/robots.txt")
    try:
        resp = fetch(url, agent_id=agent_id)
        if resp.status == 200:
            return parse_robots(resp.text)
    except Exception:
        pass
    return Robots()


# ---------------------------------------------------------------- llms.txt v2

@dataclass
class LlmsTxt:
    url: str
    found: bool = False
    title: str = ""
    summary: str = ""
    sections: dict = field(default_factory=dict)   # section -> [(name,url,note)]
    raw: str = ""


_LINK = re.compile(r"^\s*-\s*\[([^\]]+)\]\(([^)]+)\)\s*(?::\s*(.*))?$")


def load_llms_txt(base: str, agent_id: str | None = None) -> LlmsTxt:
    url = urllib.parse.urljoin(base, "/llms.txt")
    try:
        resp = fetch(url, agent_id=agent_id)
    except Exception:
        return LlmsTxt(url=url)
    if resp.status != 200 or "html" in (resp.content_type or ""):
        return LlmsTxt(url=url)
    out = LlmsTxt(url=url, found=True, raw=resp.text)
    section = "intro"
    for line in resp.text.splitlines():
        s = line.strip()
        if s.startswith("# "):
            out.title = s[2:].strip()
        elif s.startswith("## "):
            section = s[3:].strip()
            out.sections.setdefault(section, [])
        elif s.startswith("> ") and not out.summary:
            out.summary = s[2:].strip()
        else:
            m = _LINK.match(line)
            if m:
                out.sections.setdefault(section, []).append(
                    (m.group(1), m.group(2), (m.group(3) or "").strip()))
    return out


# ---------------------------------------------------------------- x402 pay

def pay_intent_header(wallet: str, network: str = "base",
                      asset: str = "USDC", amount: str = "") -> str:
    """Build the payment-intent header a 402-gated crawler presents on retry."""
    payload = {"scheme": "exact", "network": network, "asset": asset,
               "payTo": wallet, "amount": amount}
    return base64.b64encode(json.dumps(payload).encode()).decode()
