"""Sentinel contract tests; isolated trees, no network or repo writes."""
from __future__ import annotations

import copy
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from architect import sentinel  # noqa: E402

PASS = FAIL = 0


def check(label, cond, detail: object = ""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ✓ {label}")
    else:
        FAIL += 1
        print(f"  ✗ {label}  {detail}")


def write(root, name, text):
    path = os.path.join(root, name)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


def kinds(report):
    return [item["kind"] for item in report["drift"]]


def main():
    tmp = tempfile.mkdtemp(prefix="d0x-sentinel-")
    try:
        root = os.path.join(tmp, "tree")
        os.makedirs(root)
        write(root, "app.py", "print('hello')\n")
        base = sentinel.capture(root)
        same = sentinel.capture(root)
        check("same tree deterministic arch_root", base["arch_root"] == same["arch_root"])
        clean = sentinel.diff(base, same)
        check("unchanged tree is clean and silent", clean["clean"] is True and clean["drift"] == [], clean)

        write(root, "new.py", "x = 1\n")
        added = sentinel.diff(base, sentinel.capture(root))
        check("added module exactly once", kinds(added) == ["module_added"] and added["clean"] is False, kinds(added))
        os.remove(os.path.join(root, "new.py"))
        os.remove(os.path.join(root, "app.py"))
        removed = sentinel.diff(base, sentinel.capture(root))
        check("removed module is breaking", kinds(removed) == ["module_removed"] and removed["drift"][0]["severity"] == "breaking", removed)
        write(root, "app.py", "print('updated')\n")
        modified = sentinel.diff(base, sentinel.capture(root))
        check("modified module is neither added nor removed", kinds(modified) == ["module_modified"], modified)

        write(root, "app.py", "print('hello')\nimport pathlib\n")
        imported = sentinel.diff(base, sentinel.capture(root))
        check("Python AST added import edge", any(i["kind"] == "import_added" and i["target"] == "app.py -> pathlib" for i in imported["drift"]), imported)
        write(root, "app.py", "print('hello')\n")
        write(root, "requirements.txt", "requests==2.0\n")
        deps = sentinel.diff(base, sentinel.capture(root))
        check("added declared dependency", any(i["kind"] == "dep_added" and i["target"] == "requests" for i in deps["drift"]), deps)
        os.remove(os.path.join(root, "requirements.txt"))
        write(root, "app.py", "print('hello')\nif __name__ == '__main__':\n    pass\n")
        entry = sentinel.diff(base, sentinel.capture(root))
        check("added entrypoint", any(i["kind"] == "entrypoint_added" and i["target"] == "app.py" for i in entry["drift"]), entry)

        # Identical roots (same basename), opposite creation orders.
        one, two = os.path.join(tmp, "a", "project"), os.path.join(tmp, "b", "project")
        for folder, order in ((one, ("z.py", "a.py")), (two, ("a.py", "z.py"))):
            os.makedirs(folder)
            for fn in order:
                write(folder, fn, "pass\n")
        left, right = sentinel.diff(sentinel.capture(one), sentinel.capture(two)), sentinel.diff(sentinel.capture(two), sentinel.capture(one))
        check("shuffled creation order yields identical diff", left == right and left["clean"], (left, right))

        signed = sentinel.sign_baseline(base, os.path.join(tmp, "keys"))
        check("signed baseline verifies", sentinel.verify_baseline(signed, os.path.join(tmp, "keys")) == (True, ""))
        forged = copy.deepcopy(signed)
        forged["arch_root"] = "0" * 64
        check("tampered arch_root refuses without exception", sentinel.verify_baseline(forged, os.path.join(tmp, "keys"))[0] is False)
        write(one, "a.py", "pass\n")
        check("absolute path excluded from arch_root", sentinel.capture(one)["arch_root"] == sentinel.capture(two)["arch_root"])

        forged2 = copy.deepcopy(signed)
        forged2["modules"]["app.py"] = "0" * 64
        check("tampered module refuses", sentinel.verify_baseline(forged2, os.path.join(tmp, "keys"))[0] is False)
        check("missing signature refuses", sentinel.verify_baseline(base, os.path.join(tmp, "keys"))[0] is False)
        write(root, "other.go", 'import "fmt"\n')
        unsupported = sentinel.diff(base, sentinel.capture(root))
        check("unsupported language does not fabricate imports", not any(i["kind"] == "import_added" for i in unsupported["drift"]))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print(f"\n{'=' * 58}\n  {PASS} passed, {FAIL} failed\n{'=' * 58}")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
