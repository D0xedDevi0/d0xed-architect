"""Nightly architecture sentinel: rolling baseline + append-only drift log.

`sentinel capture`/`sentinel diff` answer a question when asked. This module is the
standing guard: it keeps its own baseline outside the audited tree, compares the tree
against it on every run, appends one honest log line, and returns an exit code a cron
job can act on.

State lives in a sibling directory (default `<root>/../.architect-watch/`), never inside
the audited tree -- a baseline written into the tree would become part of the architecture
and make every run self-triggering.

Exit codes
    0  clean, or a baseline was established/adopted this run
    1  drift detected and it includes at least one `breaking` item
    2  error: bad arguments, unreadable/refused baseline, capture failure
    3  drift detected, nothing breaking

Usage
    python -m architect.watch ROOT [--baseline P] [--log P] [--keys D]
                                 [--adopt] [--max-items N] [--json] [--quiet]

`--adopt` re-baselines AFTER reporting: you bless what you have just seen, never
before. A tampered baseline is refused outright -- no comparison, no auto-repair.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time

from . import auth, sentinel

DEFAULT_STATE_DIRNAME = ".architect-watch"
DEFAULT_MAX_ITEMS = 20


def _state_dir(root: str) -> str:
    return os.path.join(os.path.dirname(root), DEFAULT_STATE_DIRNAME)


def _default_paths(root: str) -> tuple[str, str, str]:
    """(baseline_path, log_path, keys_dir) -- all outside the audited tree."""
    base = os.path.basename(root.rstrip(os.sep)) or "root"
    state = _state_dir(root)
    return (os.path.join(state, f"{base}-baseline.json"),
            os.path.join(state, "drift.log"),
            os.path.join(state, ".architect-keys"))


def _inside(root: str, path: str) -> bool:
    try:
        return os.path.commonpath((root, os.path.abspath(path))) == root
    except ValueError:  # different drives / relative mix
        return False


def _stamp(ts: int | None = None) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts if ts is not None else time.time()))


def _write(path: str, text: str) -> None:
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


def _append(path: str, text: str) -> str | None:
    """Append to the log. Returns an error string instead of raising: a failed log
    write must never mask the drift result the caller is about to return."""
    try:
        parent = os.path.dirname(os.path.abspath(path))
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(text)
        return None
    except OSError as exc:
        return f"{type(exc).__name__}: {exc}"


def _summarise(drift: dict, max_items: int) -> tuple[str, list[str]]:
    """One summary line plus at most `max_items` item lines, worst severity first."""
    items = drift["drift"]
    order = {"breaking": 0, "notable": 1, "info": 2}
    ranked = sorted(items, key=lambda i: (order.get(i["severity"], 9), i["kind"], i["target"]))
    counts = {s: sum(i["severity"] == s for i in items) for s in ("breaking", "notable", "info")}
    if not items:
        summary = "no drift (architecture unchanged)"
    else:
        summary = (f"{len(items)} drift: " + ", ".join(f"{n} {s}" for s, n in counts.items() if n)
                   + f"  drift_root={drift['drift_root'][:12]}")
    shown = [f"  ! {i['severity']:8s} {i['kind']:16s} {i['target']}" for i in ranked[:max_items]]
    if len(ranked) > len(shown):
        shown.append(f"  ... {len(ranked) - len(shown)} more item(s) withheld (--max-items {max_items})")
    return summary, shown


def run(root: str, baseline_path: str, log_path: str, keys_dir: str,
        adopt: bool = False, max_items: int = DEFAULT_MAX_ITEMS) -> tuple[int, dict]:
    """One watch pass. Returns (exit_code, report). Never mutates the audited tree."""
    root = os.path.abspath(root)
    if not os.path.isdir(root):
        return 2, {"error": f"not a directory: {root}"}

    report: dict = {"root": root, "baseline_path": baseline_path, "log_path": log_path}

    warnings: list[str] = []

    if not os.path.exists(baseline_path):
        try:
            snap = sentinel.sign_baseline(sentinel.capture(root), keys_dir)
            _write(baseline_path, json.dumps(snap, indent=2, sort_keys=True) + "\n")
        except (OSError, auth.AuthError) as exc:
            return 2, {"error": f"cannot establish baseline ({type(exc).__name__}): {exc}"}
        warn = _append(log_path, f"{_stamp()}  BASELINE ESTABLISHED  {snap['arch_root'][:12]}  "
                                f"files={snap['stats']['files']}\n")
        if warn:
            warnings.append(f"log not written: {warn}")
        report |= {"status": "baseline-established", "arch_root": snap["arch_root"],
                   "files": snap["stats"]["files"]}
        if warnings:
            report["warnings"] = warnings
        return 0, report

    try:
        with open(baseline_path, encoding="utf-8") as fh:
            base = json.load(fh)
    except (OSError, ValueError) as exc:
        return 2, {"error": f"unreadable baseline ({type(exc).__name__}): {baseline_path}"}

    if "sig" in base:
        ok, reason = sentinel.verify_baseline(base, keys_dir)
        if not ok:
            # Refuse loudly. A tampered baseline must never be silently replaced.
            warn = _append(log_path, f"{_stamp()}  BASELINE REFUSED  {reason}\n")
            report |= {"status": "baseline-refused", "reason": reason}
            if warn:
                report["warnings"] = [f"log not written: {warn}"]
            return 2, report
    else:
        report["unsigned_baseline"] = True

    current = sentinel.capture(root)
    drift = sentinel.diff(base, current)
    summary, items = _summarise(drift, max_items)
    counts = {s: sum(i["severity"] == s for i in drift["drift"]) for s in ("breaking", "notable", "info")}

    head = (f"{_stamp()}  {current['arch_root'][:12]}  files={current['stats']['files']}  {summary}")
    warn = _append(log_path, "\n".join([head, *items]) + "\n")
    if warn:
        warnings.append(f"log not written: {warn}")

    report |= {"status": "clean" if drift["clean"] else "drift",
               "arch_root": current["arch_root"], "files": current["stats"]["files"],
               "counts": counts, "drift_root": drift["drift_root"],
               "summary": summary, "items": items, "drift": drift}

    if drift["clean"]:
        if warnings:
            report["warnings"] = warnings
        return 0, report

    if adopt:
        # Report first, bless second: the drift above is already logged. Adopting is an
        # explicit "I accept the current tree", so a successful adopt returns 0 -- a nightly
        # --adopt cron must not alarm every night for changes the operator opted to absorb.
        try:
            snap = sentinel.sign_baseline(current, keys_dir)
            _write(baseline_path, json.dumps(snap, indent=2, sort_keys=True) + "\n")
        except (OSError, auth.AuthError) as exc:
            report["adopt_error"] = f"{type(exc).__name__}: {exc}"
            report["warnings"] = warnings
            return 2, report
        warn = _append(log_path, f"{_stamp()}  BASELINE ADOPTED  {snap['arch_root'][:12]}  "
                                f"(superseded {str(base.get('arch_root', '?'))[:12]})\n")
        if warn:
            warnings.append(f"log not written: {warn}")
        report["adopted"] = snap["arch_root"]
        if warnings:
            report["warnings"] = warnings
        return 0, report

    if warnings:
        report["warnings"] = warnings
    return (1 if counts["breaking"] else 3), report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m architect.watch",
        description="Standing architecture sentinel: baseline vs. tree, logged for cron.")
    parser.add_argument("root", help="repository/directory to watch")
    parser.add_argument("--baseline", help="baseline JSON path (default: sibling .architect-watch/)")
    parser.add_argument("--log", help="append-only drift log path (default: sibling .architect-watch/)")
    parser.add_argument("--keys", help="Ed25519 key directory for signing/verifying the baseline")
    parser.add_argument("--adopt", action="store_true",
                        help="re-baseline AFTER reporting the drift you just saw")
    parser.add_argument("--max-items", type=int, default=DEFAULT_MAX_ITEMS,
                        help=f"max drift items to print/log (default {DEFAULT_MAX_ITEMS})")
    parser.add_argument("--json", action="store_true", help="emit the full drift report as JSON")
    parser.add_argument("--quiet", action="store_true", help="print only the summary line")
    args = parser.parse_args(argv)

    root = os.path.abspath(args.root)
    d_base, d_log, d_keys = _default_paths(root)
    baseline_path = os.path.abspath(args.baseline) if args.baseline else d_base
    log_path = os.path.abspath(args.log) if args.log else d_log
    keys_dir = os.path.abspath(args.keys) if args.keys else d_keys

    # Same safety rule the CLI enforces: state must not live inside the audited tree.
    for label, path in (("baseline", baseline_path), ("log", log_path), ("keys", keys_dir)):
        if _inside(root, path):
            print(f"[watch] {label} path must be outside the audited tree: {path}", file=sys.stderr)
            return 2
    if args.max_items < 0:
        print("[watch] --max-items must be >= 0", file=sys.stderr)
        return 2

    code, report = run(root, baseline_path, log_path, keys_dir,
                       adopt=args.adopt, max_items=args.max_items)

    for warning in report.get("warnings", []):
        print(f"[watch] {warning}", file=sys.stderr)
    if report.get("adopt_error"):
        print(f"[watch] could not adopt baseline: {report['adopt_error']}", file=sys.stderr)

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        if "error" in report:
            print(f"[watch] {report['error']}", file=sys.stderr)
            return code
        status = report["status"]
        if status == "baseline-established":
            print(f"{report['arch_root'][:12]}  BASELINE ESTABLISHED  -> {baseline_path}")
        elif status == "baseline-refused":
            print(f"[watch] baseline refused: {report['reason']}", file=sys.stderr)
        else:
            print(report["summary"])
            if not args.quiet:
                for line in report["items"]:
                    print(line)
                if report.get("adopted"):
                    print(f"baseline adopted -> {report['adopted'][:12]}")
                if not report.get("warnings"):
                    print(f"logged: {log_path}")
    return code


if __name__ == "__main__":
    raise SystemExit(main())