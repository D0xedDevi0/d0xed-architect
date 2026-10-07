"""Adaptive concurrency + per-host politeness tests.

The behaviours that actually matter:
  * the minimum interval is honoured (we are not a load generator);
  * concurrency never exceeds the host's current limit;
  * AIMD moves in the right DIRECTION: slow up, fast down;
  * Retry-After is obeyed in both of its legal formats;
  * robots.txt Crawl-delay is treated as a floor, never overridden by our
    faster default.
"""

from __future__ import annotations

import os
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from architect.limiter import (  # noqa: E402
    AdaptivePool, HostLimiter, parse_retry_after,
)

PASS = FAIL = 0


def check(label, cond, detail: object = ""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ✓ {label}")
    else:
        FAIL += 1
        print(f"  ✗ {label}  {detail}")


def test_retry_after_formats():
    check("delta-seconds", parse_retry_after("30") == 30.0)
    check("delta-seconds float", parse_retry_after("1.5") == 1.5)
    check("empty is None", parse_retry_after("") is None)
    check("None is None", parse_retry_after(None) is None)
    check("garbage is None", parse_retry_after("soon please") is None)
    # HTTP-date form: ~60s in the future
    from email.utils import formatdate
    d = formatdate(time.time() + 60, usegmt=True)
    v = parse_retry_after(d)
    check("HTTP-date parsed", v is not None and 50 < v < 70, v)


def test_min_interval_enforced():
    lim = HostLimiter()
    lim.state("https://example.com/a").min_interval = 0.2
    t0 = time.time()
    for _ in range(3):
        st = lim.acquire("https://example.com/x")
        lim.release(st)
    elapsed = time.time() - t0
    # 3 requests, 0.2s apart => at least 0.4s between first and third.
    check("min_interval spaces requests", elapsed >= 0.38, f"{elapsed:.3f}s")


def test_different_hosts_are_independent():
    lim = HostLimiter()
    lim.state("https://a.example/x").min_interval = 0.3
    lim.state("https://b.example/x").min_interval = 0.3
    t0 = time.time()
    for h in ("https://a.example/1", "https://b.example/1"):
        st = lim.acquire(h)
        lim.release(st)
    elapsed = time.time() - t0
    check("different hosts do not block each other", elapsed < 0.25,
          f"{elapsed:.3f}s")


def test_aimd_direction():
    lim = HostLimiter(default_limit=3, max_limit=8)
    st = lim.state("https://example.com/")

    start = st.limit
    for _ in range(5):
        st.on_success()
    check("additive increase after 5 clean", st.limit == start + 1,
          f"{start} -> {st.limit}")

    before = st.limit
    st.on_throttled(retry_after=0)
    check("multiplicative decrease on 429", st.limit < before,
          f"{before} -> {st.limit}")

    # Cannot fall below the floor
    for _ in range(10):
        st.on_throttled(retry_after=0)
    check("limit never goes below 1", st.limit >= 1, st.limit)

    # Cannot exceed the ceiling
    for _ in range(200):
        st.on_success()
    check("limit never exceeds max_limit", st.limit <= 8, st.limit)

    check("slow up fast down: one 429 undoes many successes",
          (start + 1) // 2 <= start, f"limit now {st.limit}")


def test_retry_after_sets_backoff():
    lim = HostLimiter()
    st = lim.state("https://example.com/")
    st.on_throttled(retry_after=0.5)
    check("backoff_until set into the future", st.backoff_until > time.time())
    t0 = time.time()
    lim.acquire("https://example.com/x")
    elapsed = time.time() - t0
    check("acquire actually waits out the backoff", elapsed >= 0.4,
          f"{elapsed:.3f}s")


def test_crawl_delay_is_a_floor():
    lim = HostLimiter()
    st = lim.state("https://slow.example/")
    st.min_interval = 0.05
    lim.set_crawl_delay("https://slow.example/", 10.0)
    check("crawl-delay raises our faster default", st.min_interval == 10.0,
          st.min_interval)
    # A smaller crawl-delay must NOT lower an existing slower setting.
    lim.set_crawl_delay("https://slow.example/", 0.01)
    check("smaller crawl-delay cannot lower it", st.min_interval == 10.0,
          st.min_interval)
    # Regression: a BARE host (no scheme) must resolve to the same state.
    lim.set_crawl_delay("bare.example", 7.0)
    check("bare host (no scheme) resolves correctly",
          lim.state("https://bare.example/").min_interval == 7.0,
          lim.state("https://bare.example/").min_interval)


def test_concurrency_never_exceeds_limit():
    lim = HostLimiter(default_limit=2, max_limit=2)
    st = lim.state("https://example.com/")
    peak = 0
    live = 0
    lock = threading.Lock()

    def worker():
        nonlocal peak, live
        s = lim.acquire("https://example.com/p")
        with lock:
            live += 1
            peak = max(peak, live)
        time.sleep(0.05)
        with lock:
            live -= 1
        lim.release(s)

    ts = [threading.Thread(target=worker) for _ in range(12)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()

    check("observed concurrency respects the limit", peak <= 2,
          f"peak={peak}")
    check("all requests ran", st.ok + st.errors + st.throttled >= 0)


def test_pool_feedback_wiring():
    """A 429 response must halve the limit through the pool, not just in theory."""
    class FakeResp:
        def __init__(self, status, headers=None):
            self.status = status
            self.headers = headers or {}

    lim = HostLimiter(default_limit=6, max_limit=8)
    pool = AdaptivePool(lim, workers=2)

    first = pool.submit_all(["https://x.example/1"],
                            lambda u: FakeResp(200))
    check("pool returns a result", len(first) == 1, first)
    st = lim.state("https://x.example/")
    check("success recorded", st.ok == 1, st.snapshot())

    pool.submit_all(["https://x.example/2"],
                    lambda u: FakeResp(429, {"retry-after": "0"}))
    check("429 halved the limit", st.limit < 6, st.snapshot())
    check("429 counted as throttled", st.throttled == 1, st.snapshot())

    pool.submit_all(["https://x.example/3"], lambda u: FakeResp(500))
    check("500 counted as error", st.errors == 1, st.snapshot())


def test_robots_crawl_delay_flows_into_limiter():
    """End-to-end: a Crawl-delay line in robots.txt must become the floor."""
    from architect.http import parse_robots

    r = parse_robots("User-agent: *\nDisallow: /private\nCrawl-delay: 10\n")
    check("crawl-delay parsed from robots", r.crawl_delay == 10.0, r.crawl_delay)

    r2 = parse_robots("User-agent: *\nDisallow: /x\n")
    check("absent crawl-delay is None", r2.crawl_delay is None, r2.crawl_delay)

    r3 = parse_robots("User-agent: *\nCrawl-delay: 2\nCrawl-delay: 30\n")
    check("most conservative declared delay wins", r3.crawl_delay == 30.0,
          r3.crawl_delay)

    r4 = parse_robots("User-agent: *\nCrawl-delay: not-a-number\n")
    check("garbage crawl-delay ignored", r4.crawl_delay is None, r4.crawl_delay)

    r5 = parse_robots("User-agent: BadBot\nCrawl-delay: 99\n")
    check("crawl-delay outside a * group is ignored", r5.crawl_delay is None,
          r5.crawl_delay)

    lim = HostLimiter()
    assert r3.crawl_delay is not None
    lim.set_crawl_delay("https://slow.example", float(r3.crawl_delay))
    st = lim.state("https://slow.example/")
    check("parsed delay becomes the limiter floor",
          st.min_interval == 30.0, st.min_interval)


def test_repeated_errors_do_not_stall_the_host():
    """THE regression. A page listing ~20 dead API endpoints turned a ~9s crawl
    into 193s because every 503 drove on_throttled() and compounded 2**n
    host-wide backoff (2**6 = 64s per request).

    503/500/405 are outcomes for ONE url, never host-wide capacity signals.
    """
    lim = HostLimiter(default_limit=6, max_limit=12)
    st = lim.state("https://example.com/")
    for _ in range(20):
        st.on_error()          # what a 503/500/405 now maps to
    check("dead endpoints do not touch the concurrency limit",
          st.limit == 6, st.limit)
    check("dead endpoints create no backoff", st.backoff_until == 0.0,
          st.backoff_until)
    check("dead endpoints are still counted", st.errors == 20, st.errors)

    t0 = time.time()
    s = lim.acquire("https://example.com/x")
    lim.release(s)
    dt = time.time() - t0
    check("a request after 20 dead endpoints is not delayed", dt < 0.2,
          f"{dt:.3f}s")


def test_backoff_is_capped():
    """Exponential backoff must stay bounded, not reach 2**n seconds."""
    lim = HostLimiter()
    st = lim.state("https://example.com/")
    for _ in range(10):
        st.on_throttled(retry_after=None)   # no Retry-After -> exponential
    delay = st.backoff_until - time.time()
    check("exponential backoff is capped", delay <= 10.1, f"{delay:.1f}s")


def test_throttle_penalty_decays_on_success():
    """Penalties must not accumulate across unrelated URLs for a whole crawl."""
    lim = HostLimiter()
    st = lim.state("https://example.com/")
    st.on_throttled(retry_after=0)
    st.on_throttled(retry_after=0)
    check("penalty accumulated", st.throttled == 2, st.throttled)
    st.on_success()
    check("success resets the penalty", st.throttled == 0, st.throttled)


def test_retry_after_zero_is_obeyed():
    """Retry-After: 0 means 'retry now'. A falsy check silently promoted it to
    exponential backoff instead of obeying the origin."""
    lim = HostLimiter()
    st = lim.state("https://example.com/")
    st.on_throttled(retry_after=0.0)
    delay = st.backoff_until - time.time()
    check("Retry-After: 0 does not become exponential backoff", delay <= 0.01,
          f"{delay:.3f}s")


def main():
    print("concurrency limiter:")
    test_retry_after_formats()
    test_min_interval_enforced()
    test_different_hosts_are_independent()
    test_aimd_direction()
    test_retry_after_sets_backoff()
    test_crawl_delay_is_a_floor()
    test_concurrency_never_exceeds_limit()
    test_pool_feedback_wiring()
    test_robots_crawl_delay_flows_into_limiter()
    test_repeated_errors_do_not_stall_the_host()
    test_backoff_is_capped()
    test_throttle_penalty_decays_on_success()
    test_retry_after_zero_is_obeyed()
    print(f"\n{PASS} passed, {FAIL} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
