#!/usr/bin/env python3
"""Render the crawl timeline as a "watch it crawl" video.

Left panel  : the real request log, one line per page as it completes.
Right panel : the site graph GROWING — nodes pop in as they are discovered and
              edges are drawn from the real parent -> child link structure
              recorded by crawl_capture.py.

Every node and every edge here is a real link the crawler actually followed.
Nothing is decorative.
"""
import json
import math
import os
import shutil
import subprocess
import sys
from urllib.parse import urlsplit

from PIL import Image, ImageDraw, ImageFont

W, H = 1600, 900
BG = (8, 11, 20)
PANEL = (10, 16, 34)
NAVY = (0, 18, 64)
CYAN = (0, 212, 255)
GREEN = (0, 230, 118)
AMBER = (255, 190, 60)
RED = (255, 69, 58)
GRAY = (140, 150, 170)
DIM = (70, 80, 100)
WHITE = (235, 238, 245)

MONO = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
MONO_BOLD = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"

OUT = "/opt/data/d0xed-architect/demo"
FRAMES = os.path.join(OUT, "crawl_frames")


def _f(p, s):
    return ImageFont.truetype(p, s)


def _grid(d, x0, y0, x1, y1, step=40, color=(15, 28, 58)):
    for x in range(x0, x1, step):
        d.line((x, y0, x, y1), fill=color, width=1)
    for y in range(y0, y1, step):
        d.line((x0, y, x1, y), fill=color, width=1)


def load(path):
    evs = [json.loads(l) for l in open(path)]
    start = next(e for e in evs if e["kind"] == "start")
    pages = [e for e in evs if e["kind"] == "page"]
    done = next((e for e in evs if e["kind"] == "done"), {})
    return start, pages, done


def layout(node_order, cx, cy, radius):
    """Stable phyllotaxis positions, computed once from ALL nodes so early
    frames don't shift as later nodes appear."""
    n = max(len(node_order), 1)
    pos = {}
    for i, u in enumerate(node_order):
        r = radius * math.sqrt((i + 0.5) / n)
        th = i * 2.399963229728653
        pos[u] = (cx + r * math.cos(th), cy + r * math.sin(th))
    return pos


def frame(start, pages, upto, pos, order, *, phase="run"):
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    _grid(d, 0, 0, W, H)

    shown = pages[:upto]
    last = shown[-1] if shown else None
    n_nodes = len({e["url"] for e in shown})
    # use the graph's own cumulative edge count so the header and the closing
    # card can never disagree (summing child-links undercounts external edges)
    n_edges = (last or {}).get("edges", 0)
    elapsed = last["t"] if last else 0.0

    # ── header ────────────────────────────────────────────────────────────
    # hand-drawn square marker — DejaVu has no 🟦 glyph, it would be a tofu box
    d.rectangle((36, 30, 54, 48), fill=CYAN)
    d.text((66, 24), "D0XED ARCHITECT", font=_f(MONO_BOLD, 30), fill=CYAN)
    d.text((36, 62), "architect crawl https://d0xeddev.com  --depth 2 --max-pages 25",
           font=_f(MONO, 17), fill=GRAY)

    badge = f"{len(shown)}/{len(pages)} PAGES · {n_edges} EDGES · {elapsed:.1f}s"
    tb = d.textbbox((0, 0), badge, font=_f(MONO_BOLD, 20))
    bw = tb[2] - tb[0] + 34
    d.rounded_rectangle((W - 36 - bw, 26, W - 36, 26 + 40), radius=8, fill=GREEN)
    d.text((W - 36 - bw + 17, 36), badge, font=_f(MONO_BOLD, 20), fill=(6, 10, 18))

    # ── left: the request log ─────────────────────────────────────────────
    lx0, ly0, lx1, ly1 = 36, 104, 706, 832
    d.rounded_rectangle((lx0, ly0, lx1, ly1), radius=14, fill=PANEL,
                        outline=CYAN, width=2)
    d.text((lx0 + 20, ly0 + 16), "CRAWL LOG", font=_f(MONO_BOLD, 20), fill=CYAN)

    y = ly0 + 56
    # robots / llms beat first
    rb = ("robots.txt FOUND" if start.get("robots_found") else "robots.txt absent")
    lb = ("llms.txt FOUND" if start.get("llms_found") else "llms.txt absent")
    d.text((lx0 + 20, y), f"→ read rules: {rb} · {lb}",
           font=_f(MONO, 16), fill=(GREEN if start.get("robots_found") else AMBER))
    y += 26
    if start.get("robots_sitemaps"):
        d.text((lx0 + 20, y), f"   sitemap declared: {start['robots_sitemaps']}",
               font=_f(MONO, 16), fill=DIM)
        y += 26
    y += 6

    body = _f(MONO, 16)
    for e in shown[-17:]:
        is_last = (e is last)
        col = CYAN if is_last else (GREEN if e["trust"] >= 90 else AMBER)
        p = e["path"]
        if len(p) > 26:
            p = p[:25] + "…"
        line = f"GET {p:<27} {e['words']:>5}w  trust {e['trust']:>3}"
        d.text((lx0 + 20, y), line, font=body, fill=col)
        if is_last:
            d.text((lx0 + 20 + 470, y), "◀", font=body, fill=CYAN)
        y += 24
    return img, d, lx0, ly0, lx1, ly1


def draw_graph(d, lx0, ly0, lx1, ly1, shown, pos, order):
    """Right panel: the real site graph, growing."""
    gx0, gy0, gx1, gy1 = 722, 104, W - 36, 832
    d.rounded_rectangle((gx0, gy0, gx1, gy1), radius=14, fill=(6, 10, 24),
                        outline=CYAN, width=2)
    d.text((gx0 + 20, gy0 + 16), "SITE GRAPH  (live)", font=_f(MONO_BOLD, 20),
           fill=CYAN)

    cx = (gx0 + gx1) / 2
    cy = (gy0 + gy1) / 2 + 14
    radius = min(gx1 - gx0, gy1 - gy0) / 2 - 62

    known = {e["url"] for e in shown}
    newly = shown[-1]["url"] if shown else None

    # edges first, so nodes sit on top — only REAL parent->child links
    for e in shown:
        if e["url"] not in pos:
            continue
        for child in e.get("children", []):
            if child in pos and child in known:
                a, b = pos[e["url"]], pos[child]
                d.line((a[0], a[1], b[0], b[1]), fill=(26, 60, 104), width=2)

    for u in order:
        if u not in known:
            continue
        x, y = pos[u]
        if u == newly:
            d.ellipse((x - 8, y - 8, x + 8, y + 8), fill=CYAN)
            d.ellipse((x - 15, y - 15, x + 15, y + 15), outline=CYAN, width=2)
        else:
            d.rectangle((x - 4, y - 4, x + 4, y + 4), fill=(0, 150, 200))

    # label the newest node
    if newly and newly in pos:
        x, y = pos[newly]
        lbl = urlsplit(newly).path or "/"
        if len(lbl) > 22:
            lbl = lbl[:21] + "…"
        d.text((x + 14, y - 9), lbl, font=_f(MONO, 15), fill=WHITE)

    if not shown:
        d.text((cx - 150, cy), "warming up…", font=_f(MONO, 20), fill=DIM)


def build(events_path):
    start, pages, done = load(events_path)
    order = []
    for e in pages:
        if e["url"] not in order:
            order.append(e["url"])
    cx, cy = (722 + (W - 36)) / 2, (104 + 832) / 2 + 14
    radius = min((W - 36) - 722, 832 - 104) / 2 - 62
    pos = layout(order, cx, cy, radius)

    scenes = []
    os.makedirs(FRAMES, exist_ok=True)

    def save(img, name):
        p = os.path.join(FRAMES, name)
        img.save(p)
        return p

    # intro card
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    _grid(d, 0, 0, W, H)
    d.text((90, 300), "WATCH IT CRAWL", font=_f(MONO_BOLD, 76), fill=CYAN)
    d.text((94, 400), "architect crawl https://d0xeddev.com", font=_f(MONO_BOLD, 34), fill=WHITE)
    d.text((94, 456), "reading robots.txt + llms.txt first, then walking the site",
           font=_f(MONO, 24), fill=GRAY)
    d.text((94, 512), "every node and edge below is a link it really followed",
           font=_f(MONO, 24), fill=AMBER)
    scenes.append((save(img, "c000.png"), 4.0))

    # one frame per crawled page — the crawl actually happening
    for i in range(1, len(pages) + 1):
        img, d, lx0, ly0, lx1, ly1 = frame(start, pages, i, pos, order)
        draw_graph(d, lx0, ly0, lx1, ly1, pages[:i], pos, order)
        scenes.append((save(img, f"c{i:03d}.png"), 0.62))

    # closing stats
    img, d, lx0, ly0, lx1, ly1 = frame(start, pages, len(pages), pos, order)
    draw_graph(d, lx0, ly0, lx1, ly1, pages, pos, order)
    yy = 700
    d.rounded_rectangle((36, 846, 470, 890), radius=10, fill=(6, 10, 24),
                        outline=GREEN, width=2)
    d.text((52, 856),
           f"CRAWL COMPLETE · {done.get('pages','?')} pages · {done.get('edges','?')} edges",
           font=_f(MONO_BOLD, 17), fill=GREEN)
    scenes.append((save(img, "c999.png"), 5.0))
    return scenes


def concat(out_path, scenes, fps=24):
    """Hold each scene for its duration by repeating frames into one numbered
    sequence, then encode in a SINGLE ffmpeg pass. A 27-input concat filter
    graph hangs; this does not."""
    seq = os.path.join(FRAMES, "seq")
    shutil.rmtree(seq, ignore_errors=True)
    os.makedirs(seq, exist_ok=True)
    n = 0
    for png, dur in scenes:
        for _ in range(max(1, int(round(dur * fps)))):
            n += 1
            shutil.copyfile(png, os.path.join(seq, f"s{n:05d}.png"))
    r = subprocess.run(
        ["ffmpeg", "-y", "-framerate", str(fps),
         "-i", os.path.join(seq, "s%05d.png"),
         "-c:v", "libx264", "-preset", "veryfast", "-crf", "20",
         "-pix_fmt", "yuv420p", "-movflags", "+faststart", out_path],
        capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit(r.stderr[-2500:])
    shutil.rmtree(seq, ignore_errors=True)
    return out_path


if __name__ == "__main__":
    ev = sys.argv[1] if len(sys.argv) > 1 else os.path.join(OUT, "crawl-events.jsonl")
    sc = build(ev)
    out = os.path.join(OUT, "d0xed-crawler-demo.mp4")
    concat(out, sc)
    print(f"frames: {len(sc)}")
    print(f"video : {out}")
    print(f"length: {sum(d for _, d in sc):.1f}s")