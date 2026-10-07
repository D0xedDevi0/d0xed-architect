"""HTTP cache: conditional GET + freshness, so repeat crawls are nearly free.

Two different wins, both worth having:

  1. **Freshness** (`Cache-Control: max-age` / `Expires`) — if the stored
     response is still fresh, we serve it with NO network call at all.
  2. **Revalidation** (ETag / Last-Modified) — if it is stale but we have a
     validator, we send `If-None-Match` / `If-Modified-Since` and a 304 costs a
     round-trip instead of a full body.

The second is what makes re-crawling a mostly-unchanged site cheap: you pay for
the headers, not the bytes.

Backed by sqlite (same dependency we already have for the graph) so a cache can
be a real file across runs, not just per-process.

Policy note: the cache sits UNDER robots/access checks, never around them. A
cached body must never be served for a URL the caller is not allowed to fetch —
callers check access first, exactly as with http.fetch().
"""
from __future__ import annotations

import email.utils
import hashlib
import json
import sqlite3
import time

from .http import Response

SCHEMA = """
CREATE TABLE IF NOT EXISTS http_cache (
    url            TEXT PRIMARY KEY,
    status         INTEGER NOT NULL,
    headers        TEXT NOT NULL,
    body           BLOB NOT NULL,
    content_type   TEXT DEFAULT '',
    etag           TEXT DEFAULT '',
    last_modified  TEXT DEFAULT '',
    cache_control  TEXT DEFAULT '',
    stored_at      REAL NOT NULL,
    fresh_until    REAL DEFAULT 0,
    body_sha256    TEXT DEFAULT '',
    hits           INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_cache_fresh ON http_cache(fresh_until);
"""


def _parse_max_age(cc: str) -> int | None:
    """Pull max-age=N out of a Cache-Control header."""
    if not cc:
        return None
    for part in cc.split(","):
        part = part.strip().lower()
        if part.startswith("max-age="):
            try:
                return int(part.split("=", 1)[1].strip())
            except ValueError:
                return None
        if part in ("no-store", "no-cache"):
            return 0
    return None


def _expires_epoch(value: str) -> float | None:
    try:
        dt = email.utils.parsedate_to_datetime(value)
        if dt is None:
            return None
        return dt.timestamp()
    except Exception:
        return None


class Entry:
    """A stored response, in the shape callers already expect."""

    __slots__ = ("url", "status", "headers", "body", "content_type", "etag",
                 "last_modified", "cache_control", "stored_at", "fresh_until",
                 "body_sha256", "hits")

    def __init__(self, row):
        (self.url, self.status, headers, self.body, self.content_type,
         self.etag, self.last_modified, self.cache_control, self.stored_at,
         self.fresh_until, self.body_sha256, self.hits) = row
        self.headers = json.loads(headers or "{}")

    @property
    def age(self) -> float:
        return time.time() - self.stored_at

    def is_fresh(self) -> bool:
        return self.fresh_until > time.time()

    def has_validator(self) -> bool:
        return bool(self.etag or self.last_modified)

    def to_response(self, cached: bool = True) -> Response:
        r = Response(
            url=self.url, status=self.status, headers=dict(self.headers),
            body=self.body, content_type=self.content_type or "",
            elapsed_ms=0,
        )
        r.cached = cached
        return r


class HttpCache:
    """sqlite-backed HTTP cache with conditional-GET support."""

    def __init__(self, path: str = ":memory:"):
        self.path = path
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.executescript(SCHEMA)
        self.db.commit()
        self.hits = 0        # served fresh, zero network
        self.revalidated = 0  # 304, network but no body
        self.misses = 0      # full fetch
        self.stores = 0
        self.bytes_saved = 0
        self._lock = __import__("threading").Lock()

    # ---------------------------------------------------------------- lookup

    def get(self, url: str) -> Entry | None:
        with self._lock:
            cur = self.db.execute(
                "SELECT url,status,headers,body,content_type,etag,last_modified,"
                "cache_control,stored_at,fresh_until,body_sha256,hits "
                "FROM http_cache WHERE url=?", (url,))
            row = cur.fetchone()
        return Entry(row) if row else None

    def note_hit(self, url: str, entry: Entry) -> None:
        with self._lock:
            self.db.execute("UPDATE http_cache SET hits=hits+1 WHERE url=?", (url,))
            self.db.commit()
        self.hits += 1
        self.bytes_saved += len(entry.body or b"")

    def note_revalidated(self, url: str, entry: Entry) -> None:
        with self._lock:
            self.db.execute(
                "UPDATE http_cache SET stored_at=?, hits=hits+1 WHERE url=?",
                (time.time(), url))
            self.db.commit()
        self.revalidated += 1
        # A 304 avoids transferring the body. Without this the cache's real
        # bandwidth win is invisible: revalidation is the common case on any
        # origin that sends `max-age=0, must-revalidate` (Vercel does).
        self.bytes_saved += len(entry.body or b"")

    def note_miss(self) -> None:
        self.misses += 1

    # ---------------------------------------------------------------- store

    def put(self, url: str, resp: Response) -> None:
        headers = resp.headers or {}
        etag = headers.get("etag", "") or ""
        last_modified = headers.get("last-modified", "") or ""
        cc = headers.get("cache-control", "") or ""

        fresh_until = 0.0
        max_age = _parse_max_age(cc)
        if max_age:
            fresh_until = time.time() + max_age
        elif headers.get("expires"):
            exp = _expires_epoch(headers["expires"])
            if exp:
                fresh_until = exp

        body = resp.body or b""
        sha = hashlib.sha256(body).hexdigest()

        with self._lock:
            self.db.execute(
                "INSERT OR REPLACE INTO http_cache "
                "(url,status,headers,body,content_type,etag,last_modified,"
                " cache_control,stored_at,fresh_until,body_sha256,hits) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,0)",
                (url, resp.status, json.dumps(headers), body,
                 resp.content_type or "", etag, last_modified, cc,
                 time.time(), fresh_until, sha))
            self.db.commit()
        self.stores += 1

    # ---------------------------------------------------------------- stats

    def stats(self) -> dict:
        return {
            "hits": self.hits,
            "revalidated": self.revalidated,
            "misses": self.misses,
            "stores": self.stores,
            "bytes_saved": self.bytes_saved,
            "entries": self.db.execute(
                "SELECT COUNT(*) FROM http_cache").fetchone()[0],
        }

    def close(self) -> None:
        try:
            self.db.close()
        except Exception:
            pass
