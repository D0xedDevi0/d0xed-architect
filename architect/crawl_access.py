"""Per-origin robots gate for crawl page requests and redirect hops."""
from __future__ import annotations

import threading
import urllib.parse

from . import http


def _host(hostname: str) -> str:
    host = hostname.lower().rstrip(".")
    return host[4:] if host.startswith("www.") else host


class CrawlAccess:
    """Authorize same-site page URLs; fetch rules for a new canonical origin."""

    def __init__(self, origin: str, robots: http.Robots):
        parsed = urllib.parse.urlsplit(origin)
        self.origin = f"{parsed.scheme}://{parsed.netloc}"
        self.scheme = parsed.scheme
        self.host = _host(parsed.hostname or "")
        self.port = parsed.port or (443 if parsed.scheme == "https" else 80)
        self._rules = {self.origin: robots}
        self._lock = threading.RLock()
        self._origin_locks: dict[str, threading.Lock] = {}

    def _validate_site(self, url: str):
        try:
            u = urllib.parse.urlsplit(url)
            port = u.port or (443 if u.scheme == "https" else 80)
        except ValueError as e:
            raise http.FetchError("invalid crawl target") from e
        if (u.scheme not in ("http", "https") or not u.hostname or
                u.username is not None or u.password is not None or
                _host(u.hostname) != self.host or
                (self.scheme == "https" and u.scheme != "https") or
                port != self.port):
            raise http.FetchError("cross-site or downgraded crawl target denied")
        return u

    @staticmethod
    def _paths(u) -> tuple[str, ...]:
        path = u.path or "/"
        candidates = [path]
        # Servers and browsers differ in when they decode/normalize paths.
        # Refuse ambiguous forms rather than let their normalization bypass a
        # literal robots prefix. Check raw AND decoded forms against rules.
        for _ in range(4):
            if ("//" in path or "\\" in path or
                    any(segment in (".", "..") for segment in path.split("/"))):
                raise http.FetchError("ambiguous crawl path denied")
            decoded = urllib.parse.unquote(path)
            if decoded == path:
                return tuple(candidates)
            path = decoded
            candidates.append(path)
        raise http.FetchError("over-encoded crawl path denied")

    def require(self, url: str) -> None:
        u = self._validate_site(url)
        paths = self._paths(u)
        # The starting site's disallow cannot be weakened by a www redirect.
        if not all(self._rules[self.origin].can_fetch(p) for p in paths):
            raise http.FetchError("robots.txt disallow")
        origin = f"{u.scheme}://{u.netloc}"
        with self._lock:
            origin_lock = self._origin_locks.setdefault(origin, threading.Lock())
        with origin_lock:
            if origin not in self._rules:
                robots_url = origin + "/robots.txt"
                # Rule discovery may redirect within the same site, but must
                # never escape to an unrelated host or downgrade HTTPS.
                try:
                    result = http.fetch(
                        robots_url, timeout=10,
                        redirect_guard=self._validate_site)
                except Exception as e:
                    raise http.FetchError("redirect-origin robots unavailable") from e
                if result.status == 200:
                    rules = http.parse_robots(result.text)
                elif result.status == 404:
                    rules = http.Robots()
                else:
                    raise http.FetchError("redirect-origin robots unavailable")
                self._rules[origin] = rules
            if not all(self._rules[origin].can_fetch(p) for p in paths):
                raise http.FetchError("robots.txt disallow")

    def allows(self, url: str) -> bool:
        try:
            self.require(url)
            return True
        except http.FetchError:
            return False
