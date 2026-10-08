"""Script-style tests for the deterministic Sentinel drift map."""

import os
import sys
import xml.etree.ElementTree as ET

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from architect.viz import drift_summary_line, sentinel_svg  # noqa: E402

PASS = FAIL = 0


def check(label, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ✓ {label}")
    else:
        FAIL += 1
        print(f"  ✗ {label}  {detail}")


def main():
    capture = {
        "version": 1, "root_name": 'demo & <repo> "one"', "captured_at": 123,
        "modules": {"z.py": "0" * 64, "a&<.py": "1" * 64,
                    "m.py": "2" * 64},
        "imports": [], "entrypoints": [], "external_deps": [],
        "stats": {"files": 3, "bytes": 12, "languages": {".py": 3}},
        "arch_root": "3" * 64,
    }
    diff = {
        "version": 1, "clean": False,
        "drift": [
            {"kind": "module_added", "target": "z.py", "severity": "notable",
             "detail": "New module."},
            {"kind": "module_modified", "target": "m.py", "severity": "info",
             "detail": "Changed module."},
            {"kind": "module_removed", "target": "old.py", "severity": "breaking",
             "detail": "Removed module."},
        ],
        "summary": {"module_added": 1, "module_modified": 1, "module_removed": 1},
        "drift_root": "4" * 64, "limits": [],
    }
    plain = sentinel_svg(capture)
    rendered = sentinel_svg(capture, diff)
    check("byte deterministic across two calls", rendered.encode("utf-8") ==
          sentinel_svg(capture, diff).encode("utf-8"))
    check("dict order does not affect layout", rendered == sentinel_svg(
        {**capture, "modules": dict(reversed(list(capture["modules"].items())))},
        {**diff, "drift": list(reversed(diff["drift"]))}))
    try:
        tree = ET.fromstring(rendered)
        valid = True
    except ET.ParseError:
        tree, valid = None, False
    check("valid standalone XML", valid and tree is not None and tree.tag == "{http://www.w3.org/2000/svg}svg")
    check("no script or remote href", "<script" not in rendered.lower()
          and 'href="http' not in rendered.lower())
    check("drift changes colors", rendered != plain and
          rendered.count('fill="#ff2d55"') > plain.count('fill="#ff2d55"') and
          rendered.count('fill="#ffb020"') > plain.count('fill="#ffb020"'))
    ns = {"s": "http://www.w3.org/2000/svg"}
    cells = [(r.attrib["fill"], r.findtext("s:title", namespaces=ns))
             for r in tree.findall("s:rect", ns) if r.find("s:title", ns) is not None] if tree is not None else []
    check("one cell per current and removed module", len(cells) == 4, str(cells))
    check("removed module has red cell", ("#ff2d55", "🟦 old.py") in cells)
    check("added and modified cells match drift", ("#00d4ff", "🟦 z.py") in cells
          and ("#ffb020", "🟦 m.py") in cells)
    check("XML special characters round trip", tree is not None
          and ("#0a1a33", "🟦 a&<.py") in cells
          and 'demo & <repo> "one"' in "".join(tree.itertext()))
    check("clean summary", drift_summary_line({"clean": True, "drift": []}) ==
          "no drift (architecture unchanged)")
    check("dirty summary", drift_summary_line(diff) ==
          "3 drift: 1 breaking, 1 notable, 1 info")
    empty = {**capture, "modules": {}, "root_name": "empty"}
    try:
        empty_xml = ET.fromstring(sentinel_svg(empty))
        empty_ok = empty_xml.tag == "{http://www.w3.org/2000/svg}svg"
    except ET.ParseError:
        empty_ok = False
    check("zero modules yields valid XML", empty_ok)
    print(f"\n{PASS} passed, {FAIL} failed")
    if FAIL:
        sys.exit(1)


if __name__ == "__main__":
    main()
