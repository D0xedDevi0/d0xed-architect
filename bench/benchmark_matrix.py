"""Bounded, per-process crawl observations. Never infer a general winner."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
from urllib.parse import urlsplit

from compare import HERE, ROOT, VENV_ARCH, VENV_C4AI, run_one

MODES = (
    ("architect-http", VENV_ARCH, os.path.join(HERE, "tool_architect.py"), {}),
    ("architect-ladder", VENV_ARCH, os.path.join(HERE, "tool_architect.py"), {"ARCH_MODE": "ladder"}),
    ("crawl4ai-browser", VENV_C4AI, os.path.join(HERE, "tool_crawl4ai.py"), {}),
)


def run_matrix(targets: list[dict], *, max_pages: int, depth: int,
               repetitions: int, output: str) -> dict:
    if not 1 <= max_pages <= 25 or not 0 <= depth <= 4 or not 1 <= repetitions <= 5:
        raise ValueError("bounds: pages 1..25, depth 0..4, repetitions 1..5")
    if not 1 <= len(targets) <= 5:
        raise ValueError("provide 1..5 explicit targets")
    for t in targets:
        u = urlsplit(t["url"])
        if u.scheme not in ("http", "https") or not u.hostname or u.username or u.password or u.fragment:
            raise ValueError("targets must be absolute HTTP(S) URLs without credentials/fragments")
        if t["kind"] not in ("static", "js") or not t["name"]:
            raise ValueError("target needs a name and static/js kind")
        if not isinstance(t.get("content_marker"), str) or not t["content_marker"]:
            raise ValueError("target needs a nonempty content_marker")
    path = Path(output)
    if path.exists():
        raise FileExistsError(path)
    try:
        commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    except (OSError, subprocess.CalledProcessError):
        commit = None
    runs = []
    for target in targets:
        for rep in range(1, repetitions + 1):
            for mode, python, script, overrides in MODES:
                env = {"BENCH_CONTENT_MARKER": target["content_marker"], **overrides}
                if mode == "architect-http":
                    env["ARCH_MODE"] = "http"
                if not os.path.isfile(python):
                    result = {"error": "runtime unavailable", "process_exit_code": None,
                              "driver_wall_s": None}
                else:
                    result = run_one(mode, python, script, target["url"], max_pages,
                                     depth, timeout=120, env_overrides=env)
                succeeded = ("error" not in result and result.get("process_exit_code") == 0)
                runs.append({"target": target["name"], "kind": target["kind"],
                             "url": target["url"], "mode": mode, "repetition": rep,
                             "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                             "success": succeeded,
                             "content_present": bool(result.get("content_marker_pages", 0)) if succeeded else None,
                             "frontier_warning": "one or zero pages reached" if succeeded and result.get("pages", 0) <= 1 and max_pages > 1 else None,
                             "metrics": result})
    artifact = {"schema": 1, "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                "commit": commit, "max_pages": max_pages, "depth": depth,
                "repetitions": repetitions, "targets": targets,
                "posture": {"architect": "strict robots, per-hop guard, HTTP-first; cold process, no cache",
                            "crawl4ai": "default robots setting; sequential arun, CacheMode.BYPASS, cold browser"},
                "runs": runs}
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    # Exclusive create keeps prior observations immutable.
    with path.open("x", encoding="utf-8") as fh:
        json.dump(artifact, fh, indent=2)
        fh.write("\n")
    return artifact


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("targets", help="JSON file with a list of named targets")
    ap.add_argument("--output", required=True, help="new JSON artifact path; will not overwrite")
    ap.add_argument("--max-pages", type=int, default=2)
    ap.add_argument("--depth", type=int, default=1)
    ap.add_argument("--repetitions", type=int, default=1)
    args = ap.parse_args()
    with open(args.targets, encoding="utf-8") as fh:
        targets = json.load(fh)
    out = run_matrix(targets, max_pages=args.max_pages, depth=args.depth,
                     repetitions=args.repetitions, output=args.output)
    print(json.dumps({"output": args.output, "runs": len(out["runs"]),
                      "successes": sum(r["success"] for r in out["runs"])}, indent=2))


if __name__ == "__main__":
    main()
