"""Production transports: Telegram API + GitHub + public web, all host-
allowlisted and SSRF-pinned. Importing this module performs NO network I/O.

The Telegram token appears ONLY inside the request URL built by the bot and is
never logged or echoed. GitHub fetches reuse `architect.safe_fetch` primitives
(public-IP-only DNS pinning, no userinfo, standard ports, bounded response
size) so no private/internal address can be reached. An optional GitHub token
is carried ONLY as an Authorization header and ONLY to api.github.com /
codeload.github.com — never logged, never sent elsewhere.
"""
from __future__ import annotations

import gzip
import io as _io
import json
import ssl
import urllib.error
import urllib.parse
import urllib.request

from architect import safe_fetch
from architect.http import MAX_BYTES, Response, UA

TELEGRAM_HOST = "api.telegram.org"
GITHUB_HOSTS = frozenset({"github.com", "api.github.com", "codeload.github.com"})
TOKEN_HOSTS = frozenset({"api.github.com", "codeload.github.com"})
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
                  timeout: float,
                  content_type: str = "application/json") -> Response:
    """POST to the Telegram API; refuses any host other than api.telegram.org.

    `content_type` defaults to JSON so every existing caller is unchanged; the
    multipart form is needed only to send a document (sendDocument).
    """
    p = urllib.parse.urlsplit(url)
    if p.scheme != "https" or (p.hostname or "").lower() != TELEGRAM_HOST:
        raise TransportError("telegram host not allowlisted")
    if not content_type.startswith(("application/json",
                                    "multipart/form-data; boundary=")):
        raise TransportError("refusing unknown content type")
    data = body if body is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"Content-Type": content_type})
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


def _transport_headers(url: str, pinned_ip: str, timeout: float,
                       extra_headers: dict | None) -> Response:
    """SSRF-pinned GET with optional extra headers (mirrors safe_fetch._transport)."""
    p, port = safe_fetch._parts(url)
    cls = (safe_fetch._PinnedHTTPS if p.scheme == "https"
           else safe_fetch._PinnedHTTP)
    conn = cls(p.hostname, port, pinned_ip, timeout)
    try:
        headers = {"Host": p.netloc, "User-Agent": UA, "Accept-Encoding": "gzip"}
        if extra_headers:
            headers.update(extra_headers)
        path = urllib.parse.urlunsplit(("", "", p.path or "/", p.query, ""))
        conn.request("GET", path, headers=headers)
        r = conn.getresponse()
        data = r.read(MAX_BYTES + 1)
        if len(data) > MAX_BYTES:
            raise safe_fetch.AccessDenied("response too large")
        hdrs = {k.lower(): v for k, v in r.getheaders()}
        if hdrs.get("content-encoding", "").lower() == "gzip":
            with gzip.GzipFile(fileobj=_io.BytesIO(data)) as f:
                data = f.read(MAX_BYTES + 1)
            if len(data) > MAX_BYTES:
                raise safe_fetch.AccessDenied("decompressed response too large")
        return Response(url, r.status, hdrs, data, hdrs.get("content-type", ""))
    finally:
        conn.close()


def _pin_fetch(url: str, timeout: float, headers: dict | None,
               allowed_hosts, token_hosts) -> Response:
    """Fetch over the SSRF-pinned transport; follow up to MAX_REDIRECTS hops
    (re-validating each hop). `headers` is forwarded, but any Authorization
    header is stripped unless the hop host is in `token_hosts`."""
    current = url
    for _ in range(MAX_REDIRECTS + 1):
        p, port = safe_fetch._parts(current)
        host = (p.hostname or "").lower()
        if host not in allowed_hosts:
            raise TransportError("host not allowlisted")
        hdr = dict(headers or {})
        if "authorization" in {k.lower() for k in hdr} and host not in token_hosts:
            hdr = {k: v for k, v in hdr.items() if k.lower() != "authorization"}
        addrs = safe_fetch._public_ips(host, port, safe_fetch._resolve)
        resp = _transport_headers(current, addrs[0], timeout, hdr)
        if resp.status in (301, 302, 303, 307, 308):
            loc = resp.headers.get("location")
            if not loc:
                raise TransportError("redirect without location")
            current = urllib.parse.urljoin(current, loc)
            continue
        return resp
    raise TransportError("too many redirects")


def github_fetch(url: str, timeout: float, headers: dict | None = None) -> Response:
    """GET a GitHub resource over the SSRF-pinned transport, allowlisted hosts
    only. An Authorization header (if present) is sent to api.github.com /
    codeload.github.com only."""
    return _pin_fetch(url, timeout, headers, GITHUB_HOSTS, TOKEN_HOSTS)


def public_fetch(url: str, timeout: float, headers: dict | None = None) -> Response:
    """GET any PUBLIC http(s) resource over the SSRF-pinned transport. No token
    is ever sent here: Authorization headers are always stripped."""
    return _pin_fetch(url, timeout, headers, _ANY_PUBLIC_HOST, frozenset())


class _AnyPublic:
    """Allowlist matcher for the public web. Every host that survives _parts()
    is already public and port-standard; this only rejects degenerate forms."""

    def __contains__(self, host: str) -> bool:
        return bool(host)


_ANY_PUBLIC_HOST = _AnyPublic()
