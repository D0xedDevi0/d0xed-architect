"""v0.3 — contracts, evidence receipts, live view.

The test that matters most is the negative one: a correct, checks-effects-
interactions contract must produce ZERO findings. A scanner that cries wolf on
safe code teaches people to ignore it, which is worse than not scanning.
"""

from __future__ import annotations

import io
import json
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from architect import contract, events, evidence as ev, nodes, tui  # noqa: E402

PASS = FAIL = 0


def check(label, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ✓ {label}")
    else:
        FAIL += 1
        print(f"  ✗ {label}  {detail}")


BAD_CONTRACT = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IDelegate { function run() external; }

contract Vault {
    mapping(address => uint256) public balances;
    address public owner;
    IDelegate public impl;

    function withdraw() public {
        uint256 bal = balances[msg.sender];
        (bool ok, ) = msg.sender.call{value: bal}("");
        balances[msg.sender] = 0;
    }

    function admin() public {
        require(tx.origin == owner, "not owner");
        impl.delegatecall(abi.encodeWithSignature("run()"));
    }

    function flush() public {
        payable(msg.sender).transfer(address(this).balance);
    }
}
"""

# Correctly written: pinned pragma, effects before interaction, call result
# checked. This must produce no findings at all.
GOOD_CONTRACT = """// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract Safe {
    mapping(address => uint256) private balances;
    address private owner;

    constructor() {
        owner = msg.sender;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        balances[msg.sender] -= amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
    }
}
"""


def rules_of(findings):
    return {f.rule for f in findings}


def main():
    tmp = tempfile.mkdtemp(prefix="d0x-v03-")
    try:
        print("\n── contract node: vulnerable fixture ──")
        bad_dir = os.path.join(tmp, "bad")
        os.makedirs(bad_dir)
        with open(os.path.join(bad_dir, "Vault.sol"), "w") as fh:
            fh.write(BAD_CONTRACT)
        bad = contract.audit_contracts(bad_dir)
        got = rules_of(bad)
        for want in ("tx_origin_auth", "delegatecall", "reentrancy_state_after_call",
                     "floating_pragma", "arbitrary_send"):
            check(f"flags {want}", want in got, f"got {sorted(got)}")
        check("every finding carries the real snippet",
              all(f.snippet and f.snippet in BAD_CONTRACT for f in bad))
        check("every finding carries a file hash",
              all(len(f.file_sha256) == 64 for f in bad))
        check("every finding carries a receipt",
              all(f.receipt.startswith("sha256:") for f in bad))

        print("\n── contract node: correct fixture (must be silent) ──")
        good_dir = os.path.join(tmp, "good")
        os.makedirs(good_dir)
        with open(os.path.join(good_dir, "Safe.sol"), "w") as fh:
            fh.write(GOOD_CONTRACT)
        good = contract.audit_contracts(good_dir)
        check("no false positives on safe code", len(good) == 0,
              f"fired {sorted(rules_of(good))}")

        print("\n── evidence: capture + manifest ──")
        one = ev.capture(bad_dir, "Vault.sol", 17, "test", "high", "detail")
        check("capture returns a receipt", one is not None)
        check("snippet is the literal source line",
              one.snippet == BAD_CONTRACT.splitlines()[16].strip())
        check("manifest root is stable",
              ev.manifest_root(bad) == ev.manifest_root(list(reversed(bad))))
        check("manifest root changes with the set",
              ev.manifest_root(bad) != ev.manifest_root(bad[:-1]))

        print("\n── verify-report: the anti-forgery check ──")
        report = ev.build_report(bad, bad_dir)
        target = os.path.join(tmp, "report.json")
        with open(target, "w") as fh:
            fh.write(ev.to_json(report))

        res = ev.verify_report(report, bad_dir)
        check("honest report verifies", res.passed and res.ok == len(bad),
              f"ok={res.ok} untouched={res.untouched}")

        # tamper: move a finding to a line that does not contain its snippet
        forged = json.loads(json.dumps(report))
        forged["findings"][0]["line"] += 1
        res2 = ev.verify_report(forged, bad_dir)
        check("forged line number is caught", not res2.passed and len(res2.untouched) == 1,
              f"untouched={res2.untouched}")

        # tamper: claim a finding exists that the file does not support
        forged2 = json.loads(json.dumps(report))
        forged2["findings"][0]["snippet"] = "require(tx.origin == owner)"
        res3 = ev.verify_report(forged2, bad_dir)
        check("forged snippet is caught", not res3.passed and res3.untouched)

        # drift: file edited after the audit
        with open(os.path.join(bad_dir, "Vault.sol"), "a") as fh:
            fh.write("\n// edited after the audit\n")
        res4 = ev.verify_report(report, bad_dir)
        check("edited file reported as stale, not as a false finding",
              res4.passed and res4.stale and res4.ok == 0,
              f"stale={res4.stale} ok={res4.ok}")

        # missing file
        os.remove(os.path.join(bad_dir, "Vault.sol"))
        res5 = ev.verify_report(report, bad_dir)
        check("deleted file is unverifiable", res5.unverifiable and not res5.passed)

        print("\n── swarm runner + event bus ──")
        os.makedirs(bad_dir, exist_ok=True)
        with open(os.path.join(bad_dir, "Vault.sol"), "w") as fh:
            fh.write(BAD_CONTRACT)
        bus = events.EventBus()
        out = nodes.run_swarm(tmp, ["contract", "repo", "bogus"], bus)
        check("unknown node is reported, not silently dropped",
              any("bogus" in e.payload.get("msg", "") for e in bus.of(events.NOTE)))
        check("runner returns findings", len(out["findings"]) > 0)
        check("runner reports a manifest root",
              len(bus.of(events.SWARM_DONE)[0].payload["manifest_root"]) == 64)
        check("each node emitted start and done",
              len(bus.of(events.NODE_START)) == 2 and len(bus.of(events.NODE_DONE)) == 2)
        check("every finding came with a receipt",
              all("receipt" in e.payload for e in bus.of(events.FINDING)))

        print("\n── live view ──")
        bus2 = events.EventBus()
        view = tui.SwarmView(bus2, width=78, color=False)
        bus2.subscribe(view.consume)
        bus2.emit(events.SWARM_START, nodes=["contract", "repo"])
        bus2.emit(events.NODE_START, node="contract")
        frame = "\n".join(view.render())
        check("pending node shows as pending", "pending" in frame)
        check("spend meter reads zero before any payment",
              "0.000000" in frame, frame.splitlines()[-1])

        bus2.emit(events.NODE_DONE, node="contract", findings=2, files=1, duration=0.5)
        bus2.emit(events.FINDING, severity="critical", rule="reentrancy_state_after_call",
                  where="Vault.sol:17", receipt="sha256:deadbeef")
        frame = "\n".join(view.render())
        check("node status updates from real events", "✓" in frame)
        check("severity counter tracks findings", view.counts["critical"] == 1)
        check("finding text appears in the event stream",
              "reentrancy_state_after_call" in frame)

        bus2.emit(events.PAYMENT, amount_usdc=0.01, payTo="0xabc")
        frame = "\n".join(view.render())
        check("spend meter moves only on a settlement event",
              "0.010000" in frame and view.settled == 1)

        bus2.emit(events.SWARM_DONE, findings=2, duration=0.9, manifest_root="a" * 64)
        frame = "\n".join(view.render())
        check("manifest root surfaces when known", "aaaaaaaaaaaa" in frame)
        check("frame is width-bounded",
              all(tui.dw(line) <= 78 for line in view.render()))

        print("\n── secret rule: real key fires, validation code does not ──")
        sec_dir = os.path.join(tmp, "sec")
        os.makedirs(sec_dir, exist_ok=True)
        body = "MIGHdCIQIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAL" + "Qk9vR2xhc3M" * 8
        with open(os.path.join(sec_dir, "real_key.js"), "w") as fh:
            fh.write("const pem = [\n"
                     '  "-----BEGIN EC PRIVATE KEY-----",\n'
                     f'  "{body}",\n'
                     '  "-----END EC PRIVATE KEY-----",\n'
                     "].join('\\n');\n")
        with open(os.path.join(sec_dir, "validation.js"), "w") as fh:
            fh.write("function detectPemKeyType(pem) {\n"
                     "  if (!pem) return 'unknown';\n"
                     "  if (pem.includes('-----BEGIN EC PRIVATE KEY-----')) return 'ec';\n"
                     "  issues.push('Missing PEM header (-----BEGIN PRIVATE KEY-----)');\n"
                     "  if (key.includes('-----BEGIN OPENSSH PRIVATE KEY-----')) return 'openssh';\n"
                     "  return 'unknown';\n"
                     "}\n")
        with open(os.path.join(sec_dir, "dup.js"), "w") as fh:
            fh.write(f'const a = "-----BEGIN EC PRIVATE KEY-----{body}";\n'
                     f'const b = "-----BEGIN RSA PRIVATE KEY-----{body}";\n')
        real = nodes.node_secrets(sec_dir).findings
        check("a real key body still fires",
              any(f.rule == "secret:private_key_block" for f in real),
              f"got {[f.rule for f in real]}")
        check("the same rule ignores a bare .includes() header check",
              all("validation.js" not in f.path for f in real),
              f"leaked {[f.path for f in real]}")
        check("two headers on one line collapse to one finding",
              len({f.receipt for f in real}) == len(real),
              f"{len(real)} findings, {len({f.receipt for f in real})} receipts")
        check("the same line is not reported twice by one rule",
              len([f for f in real if f.path.endswith("dup.js")]) <= 2,
              f"got {[f.rule for f in real if f.path.endswith('dup.js')]}")

        print("\n── secret rule: documented example stays suppressed ──")
        ex_dir = os.path.join(tmp, "ex")
        os.makedirs(ex_dir, exist_ok=True)
        with open(os.path.join(ex_dir, "settings.py"), "w") as fh:
            fh.write('AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"\n')
        with open(os.path.join(ex_dir, "live.py"), "w") as fh:
            fh.write('AWS_ACCESS_KEY_ID = "AKIA7QH2NPMX4LVZ3RTW"\n')
        ex = nodes.node_secrets(ex_dir).findings
        check("AWS's documented example is suppressed",
              not any("settings.py" in f.path for f in ex),
              f"got {[f.path for f in ex]}")
        check("a realistic-format key still fires",
              any("live.py" in f.path for f in ex),
              f"got {[f.path for f in ex]}")

        print("\n── test-path severity: annotated, never silently dropped ──")
        tp = os.path.join(tmp, "tp")
        os.makedirs(os.path.join(tp, "test"), exist_ok=True)
        os.makedirs(os.path.join(tp, "src"), exist_ok=True)
        with open(os.path.join(tp, "test", "Vault.t.sol"), "w") as fh:
            fh.write(BAD_CONTRACT)
        with open(os.path.join(tp, "src", "Vault.sol"), "w") as fh:
            fh.write(BAD_CONTRACT)
        tfind = contract.audit_contracts(tp, "contract")
        t_test = [f for f in tfind if f.path.startswith("test" + os.sep)]
        t_prod = [f for f in tfind if f.path.startswith("src" + os.sep)]
        check("test-path findings are kept, not silently dropped", len(t_test) > 0)
        check("test-path critical is stepped down",
              all(f.severity in ("high", "medium", "low", "info") for f in t_test),
              f"got {sorted({f.severity for f in t_test})}")
        check("test-path detail states why",
              all("test/mock path" in f.detail for f in t_test))
        check("production path still reports critical",
              any(f.severity == "critical" for f in t_prod),
              f"got {sorted({f.severity for f in t_prod})}")
        check("same code, different verdict by path",
              {f.severity for f in t_test} != {f.severity for f in t_prod})
        check("is_test_path agrees on both",
              contract.is_test_path("test/Vault.t.sol")
              and not contract.is_test_path("src/Vault.sol"))

        print("\n── non-tty: piping to a file still produces something honest ──")
        sio = io.StringIO()
        bus3 = events.EventBus()
        res = tui.run_with_view(tmp, ["contract"], bus3, color=False, stream=sio)
        text = sio.getvalue()
        check("non-tty run returns findings", len(res["findings"]) > 0)
        check("non-tty output has no escape codes", "\x1b[" not in text)
        check("non-tty output includes the frame", "D0XED ARCHITECT" in text)
        check("non-tty output streams real events", "contract done" in text)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print(f"\n{'=' * 58}\n  {PASS} passed, {FAIL} failed\n{'=' * 58}")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())