"""Production transports: Telegram API + GitHub, both host-allowlisted and
SSRF-pinned. Importing this module performs NO network I/O.

The Telegram token appears ONLY inside the request URL built by the bot and is
never logged or echoed. GitHub fetches reuse `architect.safe_fetch` primitives
(public-IP-only DNS pinning, no userinfo, standard ports, bounded response
size) so no private/internal address can be reached.
"""
from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.parse
import urllib.request

from architect import safe_fetch
from architect.http import Response

TELEGRAM_HOST = "api.telegram.org"
GITHUB_HOSTS = frozenset({"github.com", "api.github.com", "codeload.github.com"})
MAX_REDIRECTS = 3
TELEGRAM_BODY_CAP = 1_000_000


class TransportError(Exception):
    pass


def _ssl_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


def telegram_call(url: str, method: str, body: bytes | None,
                  timeout: float) -> Response:
    """POST to the Telegram API; refuses any host other than api.telegram.org."""
    p = urllib.parse.urlsplit(url)
    if p.scheme != "https" or (p.hostname or "").lower() != TELEGRAM_HOST:
        raise TransportError("telegram host not allowlisted")
    data = body if body is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_ssl_ctx()) as r:
            raw = r.read(TELEGRAM_BODY_CAP + 1)
            if len(raw) > TELEGRAM_BODY_CAP:
                raise TransportError("telegram response too large")
            return Response(url=url, status=r.status,
                            headers={k.lower(): v for k, v in r.headers.items()},
                            body=raw, content_type=r.headers.get("Content-Type", ""))
    except urllib.error.HTTPError as e:
        body_bytes = b""
        try:
            body_bytes = e.read(TELEGRAM_BODY_CAP)[:TELEGRAM_BODY_CAP]
        except Exception:
            pass
        return Response(url=url, status=e.code,
                        headers={k.lower(): v for k, v in (e.headers or {}).items()},
                        body=body_bytes, content_type="application/json")
    except Exception as e:
        raise TransportError(f"telegram request failed: {type(e).__name__}") from e


def github_fetch(url: str, timeout: float) -> Response:
    """GET a GitHub resource over the SSRF-pinned transport, allowlisted hosts
    only, following at most MAX_REDIRECTS hops (re-validating each hop)."""
    current = url
    for _ in range(MAX_REDIRECTS + 1):
        p, port = safe_fetch._parts(current)
        host = (p.hostname or "").lower()
        if host not in GITHUB_HOSTS:
            raise TransportError("github host not allowlisted")
        addrs = safe_fetch._public_ips(host, port, safe_fetch._resolve)
        resp = safe_fetch._transport(current, addrs[0], timeout)
        if resp.status in (301, 302, 303, 307, 308):
            loc = resp.headers.get("location")
            if not loc:
                raise TransportError("redirect without location")
            current = urllib.parse.urljoin(current, loc)
            continue
        return resp
    raise TransportError("too many redirects")
