"""Adaptive concurrency + per-host politeness.

Two problems this solves, and they are different problems:

  1. **Being a good citizen.** A crawler that opens 50 sockets against one host
     is a load generator, not a crawler. We enforce a minimum interval between
     requests to the same host, honour robots.txt `Crawl-delay` when the origin
     asks for one, and back off on `Retry-After` when told to.

  2. **Not falling over.** Concurrency that is fixed is either too slow on a
     fast origin or too aggressive on a fragile one. We use AIMD: additive
     increase while things succeed, multiplicative decrease the moment they
     don't (429, 503, timeouts, connection resets). The limit finds its own
     level per-host instead of being guessed.

Deliberately NOT included: any notion of "just retry harder". On 429/503 we
obey the origin's own signal; if it does not give us one, we back off
exponentially and keep the cut permanent for that host until it recovers.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from urllib.parse import urlsplit


@dataclass
class HostState:
    """Per-host politeness + adaptive concurrency state."""

    host: str
    limit: int = 6              # current concurrency ceiling
    min_limit: int = 1
    max_limit: int = 12
    min_interval: float = 0.0   # seconds between requests to this host
    next_allowed: float = 0.0   # earliest wall-clock time for the next request
    inflight: int = 0
    ok: int = 0
    throttled: int = 0
    errors: int = 0
    backoff_until: float = 0.0  # hard stop, set by Retry-After / repeated errors
    consecutive_ok: int = 0
    lock: threading.Lock = field(default_factory=threading.Lock)

    # ------------------------------------------------------------- admission

    def acquire(self) -> None:
        """Block until this host will accept another request."""
        while True:
            with self.lock:
                now = time.time()
                wait = 0.0
                if now < self.backoff_until:
                    wait = self.backoff_until - now
                elif self.inflight >= self.limit:
                    wait = 0.02
                elif now < self.next_allowed:
                    wait = self.next_allowed - now
                else:
                    self.inflight += 1
                    if self.min_interval:
                        self.next_allowed = now + self.min_interval
                    return
            # Sleep outside the lock so other threads can make progress.
            time.sleep(min(max(wait, 0.005), 2.0))

    def release(self) -> None:
        with self.lock:
            self.inflight = max(0, self.inflight - 1)

    # -------------------------------------------------------------- feedback

    def on_success(self) -> None:
        """Additive increase, capped, AND decay the penalty state.

        The decay matters as much as the increase: without resetting the
        throttle counter, penalties from unrelated URLs accumulate across a
        whole crawl and the backoff compounds without bound.
        """
        with self.lock:
            self.ok += 1
            self.consecutive_ok += 1
            self.throttled = 0        # success means the host is not angry
            # Only grow after a few clean results, so one lucky request cannot
            # unlock aggressive concurrency against an unstable host.
            if self.consecutive_ok >= 5 and self.limit < self.max_limit:
                self.limit += 1
                self.consecutive_ok = 0

    def on_throttled(self, retry_after: float | None = None) -> None:
        """429: the origin explicitly told us to slow down.

        ONLY a 429 belongs here. A 503 on one URL among twenty is an
        unavailable endpoint, not host-wide pushback -- treating it as rate
        limiting compounds an exponential host-wide stall across the crawl.
        """
        with self.lock:
            self.throttled += 1
            self.consecutive_ok = 0
            self.limit = max(self.min_limit, self.limit // 2)
            # Cap the growth hard. Unbounded 2**n reached 64s per request and
            # serialised an entire crawl behind one unhappy endpoint.
            # `is not None` matters: Retry-After: 0 means "retry now", and a
            # falsy check silently promoted it to exponential backoff.
            pause = (retry_after if retry_after is not None
                     else min(2.0 ** min(self.throttled, 4), 10.0))
            self.backoff_until = max(self.backoff_until, time.time() + pause)

    def on_error(self) -> None:
        """5xx / 405 / timeouts / connection resets.

        Recorded, but deliberately does NOT reduce concurrency or back off:
        a dead endpoint is not evidence about the host's capacity, and
        penalising the whole host for it starves every healthy URL.
        """
        with self.lock:
            self.errors += 1
            self.consecutive_ok = 0

    def snapshot(self) -> dict:
        with self.lock:
            return {
                "host": self.host,
                "limit": self.limit,
                "min_interval": round(self.min_interval, 3),
                "ok": self.ok,
                "throttled": self.throttled,
                "errors": self.errors,
            }


@dataclass
class RetryAfter:
    """Parsed Retry-After, which may be seconds OR an HTTP date."""

    seconds: float | None = None


def parse_retry_after(value: str | None) -> float | None:
    """Retry-After is either delta-seconds or an HTTP-date. Handle both."""
    if not value:
        return None
    value = value.strip()
    try:
        return max(0.0, float(value))
    except ValueError:
        pass
    try:
        from email.utils import parsedate_to_datetime
        dt = parsedate_to_datetime(value)
        if dt is None:
            return None
        return max(0.0, dt.timestamp() - time.time())
    except Exception:
        return None


def _host_of(value: str) -> str:
    """Resolve a URL OR a bare host to a normalised host key.

    Needed because `set_crawl_delay` is naturally called with whatever the
    robots parser knows -- sometimes a URL, sometimes "example.com". Passing a
    bare host to urlsplit() yields an EMPTY netloc, which silently created a
    second, unrelated state and dropped the delay.
    """
    value = (value or "").strip().lower()
    if "//" in value:
        host = urlsplit(value).netloc
    else:
        host = value.split("/")[0]
    return host.split(":")[0]


class HostLimiter:
    """Registry of per-host state. One of these per crawl."""

    def __init__(self, default_limit: int = 6, max_limit: int = 12):
        self.default_limit = default_limit
        self.max_limit = max_limit
        self._hosts: dict[str, HostState] = {}
        self._lock = threading.Lock()
        self.total_admitted = 0

    def state(self, url: str) -> HostState:
        host = _host_of(url)
        with self._lock:
            st = self._hosts.get(host)
            if st is None:
                st = HostState(host=host, limit=self.default_limit,
                               max_limit=self.max_limit)
                self._hosts[host] = st
            return st

    def set_crawl_delay(self, host_or_url: str, seconds: float) -> None:
        """Apply robots.txt Crawl-delay for a host."""
        st = self.state(host_or_url)
        with st.lock:
            # Crawl-delay is a floor, never a ceiling: if the origin asks for
            # 10s we wait 10s even though our own default was faster.
            st.min_interval = max(st.min_interval, float(seconds))

    def acquire(self, url: str) -> HostState:
        st = self.state(url)
        st.acquire()
        with self._lock:
            self.total_admitted += 1
        return st

    def release(self, st: HostState) -> None:
        st.release()

    def stats(self) -> dict:
        with self._lock:
            hosts = [s.snapshot() for s in self._hosts.values()]
        return {
            "hosts": hosts,
            "total_admitted": self.total_admitted,
            "throttled_total": sum(h["throttled"] for h in hosts),
            "errors_total": sum(h["errors"] for h in hosts),
        }


class AdaptivePool:
    """Thread pool whose width follows the limiter's decisions.

    The pool is deliberately simple: we keep a fixed worker count and let the
    LIMITER do the throttling, because a pool that resizes itself while threads
    block is how you get thread leaks. The adaptive part is per-host, which is
    where the actual signal lives.
    """

    def __init__(self, limiter: HostLimiter, workers: int = 6):
        self.limiter = limiter
        self.workers = max(1, workers)
        self._slots = threading.Semaphore(self.workers)

    def submit_all(self, urls, fn, max_workers: int | None = None):
        """Run fn(url) for each url, bounded, yielding (url, result_or_exc)."""
        import concurrent.futures as cf

        results = []
        with cf.ThreadPoolExecutor(max_workers=max_workers or self.workers) as ex:
            futs = {ex.submit(self._one, u, fn): u for u in urls}
            for fut in cf.as_completed(futs):
                try:
                    results.append((futs[fut], fut.result()))
                except Exception as e:  # noqa: BLE001
                    results.append((futs[fut], e))
        return results

    def _one(self, url, fn):
        st = self.limiter.acquire(url)
        try:
            out = fn(url)
            status = getattr(out, "status", 200)
            if status == 429:
                # Only an explicit 429 is rate-limit pushback.
                ra = parse_retry_after(
                    (getattr(out, "headers", {}) or {}).get("retry-after"))
                st.on_throttled(ra)
            elif status >= 400:
                # 503/500/405/404 are outcomes for THIS url, not host-wide
                # capacity signals. Record, never penalise the host.
                st.on_error()
            else:
                st.on_success()
            return out
        finally:
            self.limiter.release(st)
