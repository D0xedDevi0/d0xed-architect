"""Site / code graph in SQLite — the 'architecture' half of the Architect."""
from __future__ import annotations

import os
import sqlite3

SCHEMA = """
CREATE TABLE IF NOT EXISTS nodes (
  id INTEGER PRIMARY KEY, kind TEXT, key TEXT UNIQUE, label TEXT,
  meta TEXT, trust INTEGER DEFAULT 100);
CREATE TABLE IF NOT EXISTS edges (
  src TEXT, dst TEXT, kind TEXT, meta TEXT);
CREATE INDEX IF NOT EXISTS idx_edges_src ON edges(src);
CREATE INDEX IF NOT EXISTS idx_edges_dst ON edges(dst);
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT);
"""


class Graph:
    def __init__(self, path: str = ":memory:"):
        self.path = path
        self.db = sqlite3.connect(path)
        self.db.executescript(SCHEMA)

    def node(self, kind: str, key: str, label: str = "", meta: str = "",
             trust: int = 100):
        self.db.execute(
            "INSERT INTO nodes(kind,key,label,meta,trust) VALUES(?,?,?,?,?) "
            "ON CONFLICT(key) DO UPDATE SET label=excluded.label,"
            "meta=excluded.meta,trust=excluded.trust",
            (kind, key, label, meta, trust))

    def edge(self, src: str, dst: str, kind: str, meta: str = ""):
        self.db.execute("INSERT INTO edges(src,dst,kind,meta) VALUES(?,?,?,?)",
                        (src, dst, kind, meta))

    def set(self, k: str, v: str):
        self.db.execute("INSERT INTO meta(k,v) VALUES(?,?) "
                        "ON CONFLICT(k) DO UPDATE SET v=excluded.v", (k, v))

    def stats(self) -> dict:
        q = lambda s: self.db.execute(s).fetchone()[0]
        kinds = dict(self.db.execute(
            "SELECT kind, COUNT(*) FROM nodes GROUP BY kind").fetchall())
        ekind = dict(self.db.execute(
            "SELECT kind, COUNT(*) FROM edges GROUP BY kind").fetchall())
        return {"nodes": q("SELECT COUNT(*) FROM nodes"),
                "edges": q("SELECT COUNT(*) FROM edges"),
                "node_kinds": kinds, "edge_kinds": ekind}

    def orphans(self, limit: int = 20) -> list:
        return self.db.execute(
            "SELECT key FROM nodes WHERE kind IN ('page','file') AND key NOT IN "
            "(SELECT dst FROM edges) AND key NOT IN (SELECT src FROM edges) "
            "LIMIT ?", (limit,)).fetchall()

    def hubs(self, limit: int = 10) -> list:
        return self.db.execute(
            "SELECT dst, COUNT(*) c FROM edges GROUP BY dst "
            "ORDER BY c DESC LIMIT ?", (limit,)).fetchall()

    def commit(self):
        self.db.commit()

    def close(self):
        self.db.commit()
        self.db.close()
