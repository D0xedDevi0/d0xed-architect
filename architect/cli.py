"""D0xed Architect CLI.

  architect crawl https://example.com --depth 2 --max-pages 25 --out site.md
  architect crawl https://example.com --pay --max-spend 0.25      # settle 402s
  architect audit /path/to/repo --out audit.md --graph audit.db
  architect swarm /path/to/repo --out session          # amnesic + sealed + token
  architect reveal session.d0xbundle --token <jwt>
  architect keygen                                     # publishable JWK directory
  architect pay https://api.example.com/premium        # single paid fetch
  architect decrypt report.md.enc --passphrase-env ARCH_PASS
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import json
import os
import sys
import time
import urllib.parse

from . import audit as _audit
from . import auth as _auth
from . import crypto as _crypto
from . import extract as _extract
from . import http as _http
from . import report as _report
from . import swarm as _swarm
from . import trust as _trust
from . import x402 as _x402
from .graph import Graph

# Receipts for paywalls settled during this process run.
_PAID: list = []


# --------------------------------------------------------------------- crawl

def cmd_crawl(args) -> int:
    t0 = time.time()
    start = args.url if "://" in args.url else "https://" + args.url
    origin = "{0.scheme}://{0.netloc}".format(urllib.parse.urlsplit(start))

    robots = _http.load_robots(origin, agent_id=args.signature_agent)
    llms = _http.load_llms_txt(origin, agent_id=args.signature_agent)

    print(f"[architect] robots.txt={'found' if robots.found else 'absent'} "
          f"llms.txt={'found' if llms.found else 'absent'}", file=sys.stderr)

    # Payment is opt-in, and capped before a single request goes out.
    if getattr(args, "pay", False):
        args._policy = _x402.PayPolicy(
            enabled=True,
            max_per_call=int(round(args.max_per_call * 10 ** 6)),
            max_total=int(round(args.max_spend * 10 ** 6)))
        args._account = _x402.load_account(args.key_file)
        print(f"[architect] 💳 payment armed: ≤{args.max_spend:.4f} USDC total, "
              f"≤{args.max_per_call:.4f} USDC per call", file=sys.stderr)
    else:
        args._policy = None
        args._account = None

    queue = [start]
    if llms.found:
        for links in llms.sections.values():
            for _, u, _n in links:
                if u.startswith(origin):
                    queue.append(u)
    seen: set[str] = set()
    pages, trusts, paywalls = [], [], []
    graph = Graph(args.graph or ":memory:")

    for _depth in range(args.depth + 1):
        frontier = [u for u in queue if u not in seen][:args.max_pages * 4]
        if not frontier:
            break
        next_queue = []
        with cf.ThreadPoolExecutor(max_workers=args.concurrency) as ex:
            futs = {ex.submit(_fetch_one, u, args): u for u in frontier}
            for fut in cf.as_completed(futs):
                url = futs[fut]
                if url in seen:
                    continue
                seen.add(url)
                if len(pages) >= args.max_pages:
                    continue
                try:
                    status, resp = fut.result()
                except Exception as e:
                    print(f"[architect] ! {url}: {e}", file=sys.stderr)
                    continue
                if status == 402:
                    paywalls.append({"url": url, "price": resp})
                    continue
                if status != 200:
                    continue
                page = _extract.extract(resp, url)
                pages.append(page)
                tr = _trust.scan(
                    url, page.text, hidden_elements=page.hidden_suspicious,
                    signals=robots.signals, https=url.startswith("https://"),
                    has_llms_txt=llms.found, structured_data=bool(page.json_ld))
                trusts.append(tr)
                graph.node("page", url, label=page.title or url,
                           meta=f"words={page.word_count}", trust=tr.score)
                for href, text in page.links:
                    target = urllib.parse.urljoin(url, href).split("#")[0]
                    if target.startswith(origin) and target not in seen:
                        next_queue.append(target)
                        graph.edge(url, target, "links")
                    elif href.startswith("http"):
                        graph.edge(url, _host(target), "external")
                for mail in page.emails:
                    graph.edge(url, f"mailto:{mail}", "contact")
                print(f"[architect] ✓ {url} ({page.word_count}w, trust {tr.score})",
                      file=sys.stderr)
        queue = next_queue

    if _PAID:
        spent = sum(p["amount_usdc"] for p in _PAID)
        print(f"[architect] 💳 settled {len(_PAID)} paywall(s), {spent:.6f} USDC "
              f"authorized (not broadcast)", file=sys.stderr)

    graph.commit()
    stats = graph.stats()
    md = _report.crawl_report(start, robots, llms, pages, trusts, stats,
                              paywalls, time.time() - t0)
    _emit(md, args, graph)
    return 0


def _fetch_one(url: str, args):
    """Fetch one URL, settling a 402 when payment is armed and affordable."""
    policy = getattr(args, "_policy", None)
    if policy is not None and policy.enabled:
        try:
            r = _x402.fetch_paid(
                url, policy, account=getattr(args, "_account", None),
                timeout=args.timeout,
                headers=_http._identity_headers(args.signature_agent))
        except _x402.PaymentRequired as e:
            # Refusal is data, not a crash: record the gate and its reason.
            return 402, str(e)
        if r["paid"]:
            _PAID.append(r["receipt"])
            print(f"[architect] 💳 paid {r['amount_usdc']:.6f} USDC for {url}",
                  file=sys.stderr)
        if r["status"] == 200:
            return 200, r["content"].decode("utf-8", "replace")
        return r["status"], None

    r = _http.fetch(url, timeout=args.timeout, agent_id=args.signature_agent,
                    allow_402=False)
    if r.status == 402:
        return 402, r.headers.get("x-price") or r.headers.get("price")
    if "html" not in (r.content_type or "") and "text" not in (r.content_type or ""):
        return 204, None
    return 200, r.text


def _host(url: str) -> str:
    try:
        return "ext:" + urllib.parse.urlsplit(url).netloc
    except Exception:
        return "ext:?"


# --------------------------------------------------------------------- audit

def cmd_audit(args) -> int:
    t0 = time.time()
    root = os.path.abspath(args.path)
    graph = Graph(args.graph or ":memory:")
    res = _audit.audit_repo(root, graph=graph)
    md = _report.audit_report(res, graph.stats(), time.time() - t0)
    _emit(md, args, graph)
    sc = res.severity_counts()
    print(f"[architect] files={res.files_scanned} critical={sc['critical']} "
          f"high={sc['high']} medium={sc['medium']} low={sc['low']}", file=sys.stderr)
    return 1 if sc["critical"] else 0


# ----------------------------------------------------------------------- pay

def cmd_pay(args) -> int:
    policy = _x402.PayPolicy(
        enabled=True,
        max_per_call=int(round(args.max_per_call * 10 ** 6)),
        max_total=int(round(args.max_spend * 10 ** 6)))
    account = _x402.load_account(args.key_file)
    try:
        r = _x402.fetch_paid(args.url, policy, account=account,
                             timeout=args.timeout)
    except _x402.PaymentRequired as e:
        print(f"[architect] 🚫 {e}", file=sys.stderr)
        return 4

    if r["paid"]:
        rec = r["receipt"]
        print(f"[architect] 💳 paid {r['amount_usdc']:.6f} USDC on {rec['network']} "
              f"→ {rec['payTo']}", file=sys.stderr)
        print("[architect]    authorization signed · nothing broadcast "
              "(facilitator settles)", file=sys.stderr)
    else:
        print(f"[architect] free — HTTP {r['status']}, no payment needed",
              file=sys.stderr)

    if args.out:
        with open(args.out, "wb") as fh:
            fh.write(r["content"])
        print(f"[architect] → {args.out} ({len(r['content'])} bytes)", file=sys.stderr)
    else:
        sys.stdout.write(r["content"].decode("utf-8", "replace"))
    return 0


# --------------------------------------------------------------------- swarm

def cmd_swarm(args) -> int:
    r = _swarm.run_swarm(
        args.path, args.out or "swarm", keydir=args.keys,
        ttl=args.ttl, token_ttl=args.token_ttl, registry_path=args.registry)
    p = r["proof"]
    print(json.dumps(p, indent=2), file=sys.stderr)
    print("\n[architect] 🕸️  SWARM SESSION SEALED")
    print(f"[architect] bundle        : {p['bundle']}")
    print(f"[architect] manifest root : {p['manifest_root'][:32]}…")
    print(f"[architect] identity      : {p['identity']}")
    print(f"[architect] vault wiped   : {p['vault_wiped']} "
          f"({p['bytes_destroyed']} bytes zeroized)")
    print(f"[architect] token scope   : {p['token_scope']} (ttl {p['token_ttl_s']}s, "
          f"single-use)")
    print(f"\n[architect] TOKEN:\n{r['token']}\n")
    print(f"[architect] reveal with:\n  architect reveal {p['bundle']} "
          f"--token <token above>")
    return 0


def cmd_reveal(args) -> int:
    try:
        out = _swarm.reveal(args.bundle, args.token, keydir=args.keys,
                            registry_path=args.registry)
    except _auth.AuthError as e:
        print(f"[architect] 🚫 DENIED: {e}", file=sys.stderr)
        return 4
    if not out["integrity_ok"]:
        print("[architect] ⚠️  INTEGRITY FAILURE:")
        for p in out["problems"]:
            print("   - " + p, file=sys.stderr)
        return 5
    print(f"[architect] ✅ access granted · manifest verified "
          f"({out['claims']['sub']})", file=sys.stderr)
    if args.stdout:
        sys.stdout.write(out["payload"].get("report.md", ""))
    else:
        target = args.out or "revealed"
        os.makedirs(target, exist_ok=True)
        for k, v in out["payload"].items():
            with open(os.path.join(target, k), "w", encoding="utf-8") as fh:
                fh.write(v)
        print(f"[architect] → {target}/")
    return 0


def cmd_keygen(args) -> int:
    ks = _auth.KeyStore(args.keys).ensure()
    print(json.dumps(ks.public_bundle(), indent=2))
    print(f"\n# identity fingerprint: {_auth.fingerprint(ks.signing_pub())}",
          file=sys.stderr)
    print(f"# private keys: {args.keys}/ (mode 600) — never publish these",
          file=sys.stderr)
    return 0


def cmd_verify_token(args) -> int:
    ks = _auth.KeyStore(args.keys).ensure()
    reg = _auth.TokenRegistry(args.registry)
    try:
        claims = _auth.verify_token(args.token, ks.signing_pub(), reg,
                                    scope=args.scope)
    except _auth.AuthError as e:
        print(f"[architect] 🚫 {e}", file=sys.stderr)
        return 4
    print(json.dumps(claims, indent=2))
    return 0


# --------------------------------------------------------------------- emit

def _emit(md: str, args, graph: Graph):
    data = md.encode("utf-8")
    out = args.out
    if getattr(args, "encrypt", False):
        pw = _passphrase(args)
        if not pw:
            print("[architect] --encrypt needs ARCHITECT_PASSPHRASE or --passphrase-env",
                  file=sys.stderr)
            sys.exit(2)
        blob = _crypto.encrypt(data, pw, aad=(args.out or "").encode())
        out = (out or "architect-report.md") + ".enc"
        with open(out, "wb") as fh:
            fh.write(blob)
        print(f"[architect] 🔒 encrypted → {out} ({len(blob)} bytes, AES-256-GCM/scrypt)")
    else:
        out = out or "architect-report.md"
        with open(out, "w", encoding="utf-8") as fh:
            fh.write(md)
        print(f"[architect] → {out}")
    if getattr(args, "graph", None):
        graph.close()
    if getattr(args, "stdout", False):
        sys.stdout.write(md)


def _passphrase(args) -> str | None:
    if getattr(args, "passphrase_env", None):
        return os.environ.get(args.passphrase_env)
    return os.environ.get("ARCHITECT_PASSPHRASE")


def cmd_decrypt(args) -> int:
    pw = _passphrase(args)
    if not pw:
        print("[architect] need ARCHITECT_PASSPHRASE or --passphrase-env", file=sys.stderr)
        return 2
    with open(args.path, "rb") as fh:
        blob = fh.read()
    try:
        data = _crypto.decrypt(blob, pw)
    except Exception as e:
        print(f"[architect] decrypt failed: {e}", file=sys.stderr)
        return 3
    sys.stdout.buffer.write(data)
    return 0


# --------------------------------------------------------------------- main

def cmd_place(args) -> int:
    """Place swarm nodes on a target, live view, and emit a verifiable report."""
    from . import events as _events, evidence as _ev, nodes as _nodes, tui as _tui

    root = os.path.abspath(args.path)
    if not os.path.isdir(root):
        print(f"not a directory: {root}", file=sys.stderr)
        return 2

    names = [n.strip() for n in (args.nodes or "").split(",") if n.strip()]
    if not names:
        names = list(_nodes.DEFAULT_NODES)
    bad = [n for n in names if n not in _nodes.NODES]
    if bad:
        print(f"unknown node(s): {', '.join(bad)}", file=sys.stderr)
        print(f"available: {', '.join(_nodes.NODES)}", file=sys.stderr)
        return 2

    bus = _events.EventBus()
    result = _tui.run_with_view(
        root, names, bus, cap=args.max_spend or 0.0,
        width=args.width, color=False if args.no_color else None)
    findings = result.get("findings", [])

    report = _ev.build_report(findings, root, nodes=result.get("nodes", {}),
                              duration=result.get("duration", 0.0))
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            fh.write(_ev.to_json(report))
        print(f"\nreport written : {args.json}")
        print(f"manifest root  : {report['manifest_root']}")
        print(f"verify with    : architect verify-report {args.json}")

    counts = report["counts"]
    hot = [f for f in findings if f.severity in ("critical", "high")]
    if hot:
        print("\ntop findings (each is a receipt, not a claim):")
        for f in hot[:args.top]:
            print(f"  {f.severity:<8} {f.rule:<32} {f.path}:{f.line}")
            print(f"           {f.snippet[:88]}")
            print(f"           {f.receipt}")
    print(f"\n{counts['critical']} critical · {counts['high']} high · "
          f"{counts['medium']} medium · {counts['low']} low")
    return 1 if counts["critical"] else 0


def cmd_verify_report(args) -> int:
    """Re-hash the tree and confirm every finding still points at its bytes."""
    import json as _json

    from . import evidence as _ev

    try:
        with open(args.report, "r", encoding="utf-8") as fh:
            report = _json.load(fh)
    except (OSError, ValueError) as exc:
        print(f"cannot read report: {exc}", file=sys.stderr)
        return 2

    root = os.path.abspath(args.root or report.get("root") or ".")
    res = _ev.verify_report(report, root)
    total = len(report.get("findings", []))

    print(f"report       : {args.report}")
    print(f"root         : {root}")
    print(f"findings     : {total}")
    print(f"verified     : {res.ok}")
    print(f"manifest root: {report.get('manifest_root', '')}")
    if res.stale:
        print(f"stale files  : {len(set(res.stale))} — changed since the audit, "
              "findings were true at the audited revision")
        for p in sorted(set(res.stale))[:5]:
            print(f"   ~ {p}")
    if res.unverifiable:
        print(f"unverifiable : {len(set(res.unverifiable))} — file missing or unreadable")
        for p in sorted(set(res.unverifiable))[:5]:
            print(f"   ? {p}")
    if res.untouched:
        print(f"mismatch     : {len(res.untouched)} — snippet no longer on the stated line")
        for p in res.untouched[:5]:
            print(f"   ! {p}")

    if res.passed and not res.stale:
        print("\nVERIFIED — every finding reproduces from this tree.")
        return 0
    if res.passed:
        print("\nPASSED WITH DRIFT — findings were valid at the audited revision; "
              "files have since changed.")
        return 0
    print("\nFAILED — the report does not reproduce. Treat it as untrusted.")
    return 1


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        prog="architect",
        description="D0xed Architect — agentic crawler + amnesic code auditor")
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp):
        sp.add_argument("--out", help="output file/dir")
        sp.add_argument("--graph", help="sqlite graph path")
        sp.add_argument("--encrypt", action="store_true", help="AES-256-GCM the output")
        sp.add_argument("--passphrase-env", help="env var holding the passphrase")
        sp.add_argument("--stdout", action="store_true", help="also print report")

    def swarmish(sp):
        sp.add_argument("--keys", default=".architect-keys",
                        help="key directory (default .architect-keys)")
        sp.add_argument("--registry", default=".architect-tokens.db",
                        help="single-use token registry")
        sp.add_argument("--out", help="output file/dir")
        sp.add_argument("--stdout", action="store_true", help="print instead of writing")

    def payable(sp):
        sp.add_argument("--pay", action="store_true",
                        help="settle HTTP 402 gates via x402 and keep crawling")
        sp.add_argument("--max-spend", type=float, default=0.25,
                        help="USDC ceiling for the whole run (default 0.25)")
        sp.add_argument("--max-per-call", type=float, default=0.05,
                        help="USDC ceiling per settlement (default 0.05)")
        sp.add_argument("--key-file",
                        help="EVM key file (default $D0XED_PAY_KEY_FILE)")

    c = sub.add_parser("crawl", help="crawl a site and map it")
    c.add_argument("url")
    c.add_argument("--depth", type=int, default=1)
    c.add_argument("--max-pages", type=int, default=25)
    c.add_argument("--concurrency", type=int, default=6)
    c.add_argument("--timeout", type=int, default=20)
    c.add_argument("--signature-agent", help="Web Bot Auth key-directory URL")
    payable(c)
    common(c)
    c.set_defaults(fn=cmd_crawl)

    a = sub.add_parser("audit", help="audit a local codebase")
    a.add_argument("path")
    common(a)
    a.set_defaults(fn=cmd_audit)

    y = sub.add_parser("pay", help="fetch a URL, settling an HTTP 402 via x402")
    y.add_argument("url")
    y.add_argument("--max-spend", type=float, default=0.10,
                   help="USDC ceiling for this call (default 0.10)")
    y.add_argument("--max-per-call", type=float, default=0.05,
                   help="USDC ceiling (default 0.05)")
    y.add_argument("--key-file",
                   help="EVM key file (default $D0XED_PAY_KEY_FILE)")
    y.add_argument("--timeout", type=int, default=30)
    y.add_argument("--out", help="write body to file")
    y.set_defaults(fn=cmd_pay)

    s = sub.add_parser("swarm", help="amnesic audit session: seal + token + wipe")
    s.add_argument("path")
    s.add_argument("--ttl", type=int, default=1800, help="vault lifetime (s)")
    s.add_argument("--token-ttl", type=int, default=900, help="token lifetime (s)")
    swarmish(s)
    s.set_defaults(fn=cmd_swarm)

    r = sub.add_parser("reveal", help="decrypt a swarm bundle with a token")
    r.add_argument("bundle")
    r.add_argument("--token", required=True)
    swarmish(r)
    r.set_defaults(fn=cmd_reveal)

    k = sub.add_parser("keygen", help="create/publish the node key directory")
    swarmish(k)
    k.set_defaults(fn=cmd_keygen)

    v = sub.add_parser("verify-token", help="verify + burn a capability token")
    v.add_argument("token")
    v.add_argument("--scope")
    swarmish(v)
    v.set_defaults(fn=cmd_verify_token)

    d = sub.add_parser("decrypt", help="decrypt an .enc report")
    d.add_argument("path")
    d.add_argument("--passphrase-env")
    d.set_defaults(fn=cmd_decrypt)

    pl = sub.add_parser("place", help="place swarm nodes on a target (live view + report)")
    pl.add_argument("path")
    pl.add_argument("--nodes", default="", help="repo,secrets,contract,deps")
    pl.add_argument("--json", help="write the verifiable report JSON here")
    pl.add_argument("--top", type=int, default=10)
    pl.add_argument("--width", type=int, default=78)
    pl.add_argument("--no-color", action="store_true")
    pl.add_argument("--max-spend", type=float, default=0.0)
    pl.set_defaults(fn=cmd_place)

    vr = sub.add_parser("verify-report",
                        help="re-verify a report against the tree it audited")
    vr.add_argument("report")
    vr.add_argument("--root", help="defaults to the root recorded in the report")
    vr.set_defaults(fn=cmd_verify_report)

    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())