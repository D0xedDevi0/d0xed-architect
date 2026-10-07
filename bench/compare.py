"""Benchmark driver: run each crawler in its OWN process, then compare.

    python bench/compare.py <url> [max_pages] [depth]

Each tool gets a separate interpreter, so peak RSS is attributable and one
tool's imports/heap cannot inflate another's numbers.
"""
import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
VENV_ARCH = os.path.join(ROOT, ".venv", "bin", "python")
VENV_C4AI = os.path.join(HERE, ".venv", "bin", "python")

RUNNERS = [
    ("d0xed-architect", VENV_ARCH, os.path.join(HERE, "tool_architect.py")),
    ("crawl4ai", VENV_C4AI, os.path.join(HERE, "tool_crawl4ai.py")),
]


def run_one(name, python, script, url, max_pages, depth, timeout=900):
    env = dict(os.environ, PYTHONWARNINGS="ignore")
    cmd = [python, script, url, str(max_pages), str(depth)]
    t0 = time.time()
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           env=env, cwd=ROOT)
    except subprocess.TimeoutExpired:
        return {"tool": name, "error": f"timeout after {timeout}s",
                "wall_s": round(time.time() - t0, 1)}
    for line in (p.stdout or "").splitlines():
        if line.startswith("BENCH_JSON "):
            return json.loads(line[len("BENCH_JSON "):])
    tail = ((p.stderr or "") + (p.stdout or "")).strip().splitlines()[-6:]
    return {"tool": name, "error": "no metrics emitted", "detail": tail,
            "wall_s": round(time.time() - t0, 1)}


def main():
    url = sys.argv[1] if len(sys.argv) > 1 else "https://d0xeddev.com"
    max_pages = int(sys.argv[2]) if len(sys.argv) > 2 else 25
    depth = int(sys.argv[3]) if len(sys.argv) > 3 else 2

    results = []
    for name, python, script in RUNNERS:
        if not os.path.exists(python):
            results.append({"tool": name, "error": f"missing venv {python}"})
            continue
        r = run_one(name, python, script, url, max_pages, depth)
        results.append(r)
        print(f"  .. {name}: {json.dumps(r)[:150]}", file=sys.stderr)

    out = {"url": url, "max_pages": max_pages, "depth": depth,
           "results": results}
    dest = os.path.join(HERE, "bench-results.json")
    with open(dest, "w") as fh:
        json.dump(out, fh, indent=2)
    print(json.dumps(out, indent=2))
    print(f"\nwritten: {dest}")


if __name__ == "__main__":
    main()