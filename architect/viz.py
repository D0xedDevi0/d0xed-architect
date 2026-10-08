"""Deterministic, read-only SVG view of a Sentinel capture and its drift."""

from __future__ import annotations

from html import escape


BACKGROUND = "#001240"
CYAN = "#00d4ff"
AMBER = "#ffb020"
RED = "#ff2d55"
NAVY = "#0a1a33"
COLORS = {
    "module_added": CYAN,
    "module_modified": AMBER,
    "module_removed": RED,
}
COLS = 24


def _xml(value: object) -> str:
    """Escape text and attributes, replacing characters forbidden by XML 1.0."""
    text = str(value)
    safe = "".join(
        char if (ord(char) in (9, 10, 13) or 32 <= ord(char) <= 0xD7FF
                 or 0xE000 <= ord(char) <= 0xFFFD
                 or 0x10000 <= ord(char) <= 0x10FFFF) else "\ufffd"
        for char in text
    )
    return escape(safe, quote=True)


def drift_summary_line(diff: dict) -> str:
    """Report actual drift counts, without interpreting drift as a vulnerability."""
    if not diff["drift"]:
        return "no drift (architecture unchanged)"
    counts = {level: 0 for level in ("breaking", "notable", "info")}
    for item in diff["drift"]:
        counts[item["severity"]] += 1
    return (f'{len(diff["drift"])} drift: '
            + ", ".join(f"{counts[level]} {level}" for level in counts))


def sentinel_svg(capture: dict, diff: dict | None = None) -> str:
    """Render current modules plus any removed modules on a stable sorted grid."""
    modules = set(capture["modules"])
    changes = {}
    if diff is not None:
        for item in diff["drift"]:
            if item["kind"] in COLORS:
                changes[item["target"]] = item["kind"]
        modules.update(path for path, kind in changes.items()
                       if kind == "module_removed")
    paths = sorted(modules)
    counts = {level: 0 for level in ("breaking", "notable", "info")}
    if diff is not None:
        for item in diff["drift"]:
            counts[item["severity"]] += 1

    grid_rows = max(1, (len(paths) + COLS - 1) // COLS)
    grid_bottom = 130 + grid_rows * 32
    legend_top = grid_bottom + 35
    footer_y = legend_top + max(1, len(paths)) * 22 + 24
    height = footer_y + 28
    lines = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="1100" height="{height}" '
        f'viewBox="0 0 1100 {height}">',
        f'<rect width="1100" height="{height}" fill="{BACKGROUND}"/>',
        f'<text x="24" y="34" fill="{CYAN}" font-family="monospace" '
        f'font-size="19">🟦 SENTINEL DRIFT MAP</text>',
        f'<text x="24" y="61" fill="{CYAN}" font-family="monospace" '
        f'font-size="14">🟦 {_xml(capture["root_name"])}  '
        f'{len(capture["modules"])} current modules</text>',
    ]
    for index, level in enumerate(counts):
        color = {"breaking": RED, "notable": CYAN, "info": AMBER}[level]
        lines.append(f'<text x="{24 + index * 345}" y="93" fill="{color}" '
                     f'font-family="monospace" font-size="14">'
                     f'🟦 {level}: {counts[level]}</text>')

    for index, path in enumerate(paths):
        kind = changes.get(path)
        color = COLORS.get(kind or "", NAVY)
        x = 24 + (index % COLS) * 44
        y = 130 + (index // COLS) * 32
        lines.append(f'<rect x="{x}" y="{y}" width="34" height="22" '
                     f'fill="{color}" stroke="{CYAN}" stroke-width="1">'
                     f'<title>🟦 {_xml(path)}</title></rect>')
    if not paths:
        lines.append(f'<text x="24" y="{legend_top}" fill="{CYAN}" '
                     f'font-family="monospace" font-size="13">🟦 no modules</text>')
    for index, path in enumerate(paths):
        color = COLORS.get(changes.get(path) or "", NAVY)
        # Cyan text on untouched modules stays legible against the background.
        text_color = CYAN if color == NAVY else color
        lines.append(f'<text x="24" y="{legend_top + index * 22}" '
                     f'fill="{text_color}" font-family="monospace" font-size="13">'
                     f'🟦 {index + 1:04d} {_xml(path)}</text>')
    footer = drift_summary_line(diff) if diff is not None else "baseline only (no comparison)"
    lines.append(f'<text x="24" y="{footer_y}" fill="{CYAN}" '
                 f'font-family="monospace" font-size="13">🟦 {_xml(footer)}</text>')
    lines.append('</svg>')
    return "\n".join(lines)
