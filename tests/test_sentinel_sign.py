"""Signed drift contract: hermetic trees, public-key-only second process."""
from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from architect import auth, sentinel  # noqa: E402

PASS = FAIL = 0


def check(label, cond, detail: object = ""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ✓ {label}")
    else:
        FAIL += 1
        raise AssertionError(f"{label}: {detail}")


class SignedDriftTests(unittest.TestCase):
    def test_contract(self):
        with tempfile.TemporaryDirectory(prefix="d0x-sentinel-sign-") as tmp:
            tree = os.path.join(tmp, "tree")
            os.mkdir(tree)
            with open(os.path.join(tree, "app.py"), "w", encoding="utf-8") as fh:
                fh.write("pass\n")
            baseline = sentinel.capture(tree)
            with open(os.path.join(tree, "app.py"), "w", encoding="utf-8") as fh:
                fh.write("print('changed')\n")
            report = {**sentinel.diff(baseline, sentinel.capture(tree)),
                      "baseline": {"arch_root": baseline["arch_root"]}}
            keys_a, keys_b = os.path.join(tmp, "keys-a"), os.path.join(tmp, "keys-b")
            signed = sentinel.sign_drift(report, keys_a)
            check("in-process sign then verify", signed is not report and
                  "sig" not in report and sentinel.verify_drift(signed, keys_a) == (True, "ok"))

            jsonfile = os.path.join(tmp, "report.json")
            pubfile = os.path.join(tmp, "node-signing.pub")
            with open(jsonfile, "w", encoding="utf-8") as fh:
                json.dump(signed, fh)
            pub = auth.KeyStore(keys_a).signing_pub()
            with open(pubfile, "wb") as fh:
                fh.write(pub.public_bytes(auth.serialization.Encoding.PEM,
                                          auth.serialization.PublicFormat.SubjectPublicKeyInfo))
            code = "from architect.cli import main; raise SystemExit(main(['sentinel', 'verify', __import__('sys').argv[1], '--keys', __import__('sys').argv[2]]))"
            run = subprocess.run([sys.executable, "-c", code, jsonfile, pubfile],
                                 capture_output=True, text=True, cwd=os.path.dirname(os.path.dirname(__file__)))
            check("second process verifies JSON with public key only",
                  run.returncode == 0 and run.stdout.strip() == "ok", (run.stdout, run.stderr))

            for label, change in (
                ("tampered drift_root refused", lambda d: d.update(drift_root="0" * 64)),
                ("tampered single drift target refused", lambda d: d["drift"][0].update(target="evil.py")),
                ("tampered baseline arch_root refused", lambda d: d["baseline"].update(arch_root="0" * 64)),
            ):
                altered = copy.deepcopy(signed)
                change(altered)
                check(label, sentinel.verify_drift(altered, pubfile) ==
                      (False, "signature verification failed"))
            altered = copy.deepcopy(signed)
            del altered["sig"]
            check("deleted sig refused clearly", sentinel.verify_drift(altered, pubfile) ==
                  (False, "missing signature"))
            sentinel.sign_drift(report, keys_b)
            check("wrong keydir refused", sentinel.verify_drift(signed, keys_b) ==
                  (False, "signing identity mismatch"))
            check("empty dict never raises", sentinel.verify_drift({})[0] is False)
            check("junk sig never raises", sentinel.verify_drift({"sig": "junk"}) ==
                  (False, "missing signature"))
            print(f"  {PASS} passed, {FAIL} failed")


if __name__ == "__main__":
    unittest.main()
