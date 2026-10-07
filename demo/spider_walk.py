#!/usr/bin/env python3
"""Procedural spider that walks the crawl graph.

No sprite sheets, no keyframes. The body follows a tour of the nodes the
crawler actually found; eight legs solve their own joint angles with
two-link inverse kinematics every frame, and each foot picks the nearest
real node within reach to plant on. Legs step in an alternating tetrapod
gait, so the body is always supported.

Render:  spider_walk.py <crawl-events.jsonl> <out.mp4>
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
CYAN = (0, 212, 255)
CYAN_D = (0, 120, 160)
CYAN_L = (150, 240, 255)
NAVY = (14, 32, 70)
GREEN = (0, 230, 118)
AMBER = (255, 190, 60)
GRAY = (140, 150, 170)
DIM = (52, 62, 84)
WHITE = (232, 238, 248)

FPS = 24
MONO_B = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
MONO = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
OUTDIR = "/opt/data/d0xed-architect/demo"
FRAMES = os.path.join(OUTDIR, "spider_frames")


def clamp(v, lo, hi):
    return lo if v < lo else (hi if v > hi else v)


def lerp(a, b, t):
    return a + (b - a) * t


def seg(d, p0, p1, w0, w1, fill):
    """Tapered capsule between two joints."""
    dx, dy = p1[0] - p0[0], p1[1] - p0[1]
    L = math.hypot(dx, dy) or 1.0
    nx, ny = -dy / L, dx / L
    d.polygon([(p0[0] + nx * w0, p0[1] + ny * w0),
               (p1[0] + nx * w1, p1[1] + ny * w1),
               (p1[0] - nx * w1, p1[1] - ny * w1),
               (p0[0] - nx * w0, p0[1] - ny * w0)], fill=fill)


def poly(d, pts, fill=None, outline=None, width=2):
    """Angular plate — the D0xed Dev look is faceted, not soft."""
    if fill:
        d.polygon(pts, fill=fill)
    if outline:
        d.line(list(pts) + [pts[0]], fill=outline, width=width, joint="curve")


def ik(hip, foot, l1, l2, side):
    """Two-link IK. Returns the knee. side=+1/-1 picks the elbow solution."""
    dx, dy = foot[0] - hip[0], foot[1] - hip[1]
    dist = math.hypot(dx, dy)
    dist = clamp(dist, 1.0, (l1 + l2) * 0.999)
    base = math.atan2(dy, dx)
    ca = clamp((l1 * l1 + dist * dist - l2 * l2) / (2 * l1 * dist), -1.0, 1.0)
    th = base + math.acos(ca) * side
    return (hip[0] + l1 * math.cos(th), hip[1] + l1 * math.sin(th))


class Leg:
    """One leg: a rest pose, a planted foot, and a step cycle."""

    def __init__(self, idx, side, rest_angle, reach, l1, l2):
        self.idx = idx
        self.side = side                 # -1 left, +1 right
        self.rest_angle = rest_angle     # local angle from body forward
        self.reach = reach               # how far the foot sits from the hip
        self.l1, self.l2 = l1, l2
        self.foot = None
        self.step_t = 1.0                # 1.0 = planted
        self.step_from = None
        self.step_to = None
        self.gripping = None             # node url currently held

    def rest_point(self, bx, by, ba):
        a = ba + self.rest_angle * self.side
        return (bx + math.cos(a) * self.reach, by + math.sin(a) * self.reach)

    def update(self, bx, by, ba, nodes, hip_reach, claimed=None, taken=None):
        target = self.rest_point(bx, by, ba)
        self.gripping = None
        # A foot prefers a REAL node, but only inside its own angular sector AND
        # only if no other leg has claimed it — shared nodes collapse the splay.
        want_ang = ba + self.rest_angle * self.side
        best, bestd, bestu = None, 1e9, None
        for url, (nx, ny) in nodes.items():
            if claimed is not None and url in claimed:
                continue
            dx, dy = nx - bx, ny - by
            dist = math.hypot(dx, dy)
            if not (hip_reach[0] <= dist <= hip_reach[1]):
                continue
            diff = abs((math.atan2(dy, dx) - want_ang + math.pi) % (2 * math.pi) - math.pi)
            if diff > 0.35:
                continue
            score = dist * 0.5 + diff * 240
            if score < bestd:
                best, bestd, bestu = (nx, ny), score, url
        if best is not None:
            ang_b = math.atan2(best[1] - by, best[0] - bx)
            # reject a grip that would land on top of an already-taken foot
            if any(abs((ang_b - a + math.pi) % (2 * math.pi) - math.pi) < 0.42
                   for a in (taken or [])):
                best = None
        if best is not None:
            target = best
            self.gripping = bestu
            if claimed is not None and bestu is not None:
                claimed.add(bestu)
            if taken is not None:
                taken.append(math.atan2(best[1] - by, best[0] - bx))

        if self.step_t >= 1.0:
            moved = math.hypot(self.foot[0] - target[0], self.foot[1] - target[1])
            if moved > 26:
                self.step_from = self.foot
                self.step_to = target
                self.step_t = 0.0
        else:
            self.step_to = target
            self.step_t = min(1.0, self.step_t + 0.14)
            t = self.step_t
            e = t * t * (3 - 2 * t)                      # smoothstep
            self.foot = (lerp(self.step_from[0], self.step_to[0], e),
                         lerp(self.step_from[1], self.step_to[1], e))
            lift = math.sin(math.pi * t) * 34            # arc up mid-step
            self.foot = (self.foot[0], self.foot[1] - lift)
            if t >= 1.0:
                self.foot = self.step_to

    def planted(self):
        return self.step_t >= 1.0

    def draw(self, d, hip):
        foot = self.foot
        knee = ik(hip, foot, self.l1, self.l2, self.side)
        # dark separation pass first, so limbs read against the web behind them
        seg(d, hip, knee, 12, 9, (2, 9, 20))
        seg(d, knee, foot, 9, 4, (2, 9, 20))
        # lit limb
        seg(d, hip, knee, 8.5, 5.5, CYAN)
        seg(d, knee, foot, 5.5, 2.2, CYAN_L)
        # hard joint hardware: a housing ring at the knee, a claw at the tip
        d.ellipse((knee[0] - 5, knee[1] - 5, knee[0] + 5, knee[1] + 5),
                  fill=(6, 14, 26), outline=CYAN_L, width=2)
        d.ellipse((knee[0] - 2, knee[1] - 2, knee[0] + 2, knee[1] + 2), fill=WHITE)
        d.ellipse((foot[0] - 3, foot[1] - 3, foot[0] + 3, foot[1] + 3), fill=WHITE)
        if not self.planted():
            d.ellipse((foot[0] - 9, foot[1] - 9, foot[0] + 9, foot[1] + 9),
                      outline=CYAN_L, width=2)


class Spider:
    def __init__(self, l1=96.0, l2=112.0, reach=190.0):
        self.bx, self.by, self.ba = 0.0, 0.0, 0.0
        self.legs = []
        # 6 legs, 3 per side. rest_angle = pi/2 + offset, so `ba + rest_angle*side`
        # fans each leg perpendicular to the body and OUT to its own side.
        # Six reads cleaner than eight and looks more like a machine.
        spread = [math.pi / 2 + o for o in (-0.62, 0.0, 0.62)]
        for i, a in enumerate(spread):
            self.legs.append(Leg(i, -1, a, reach * (0.82 + 0.06 * i), l1, l2))
        for i, a in enumerate(spread):
            self.legs.append(Leg(i + 4, +1, a, reach * (0.82 + 0.06 * i), l1, l2))
        self.hip_reach = (60.0, reach * 1.32)
        self.gait = 0

    def place(self, x, y, a):
        self.bx, self.by, self.ba = x, y, a
        if self.legs[0].foot is None:
            for lg in self.legs:
                lg.foot = lg.rest_point(x, y, a)
                lg.step_t = 1.0

    def update(self, nodes):
        # legs claim nodes exclusively, so two feet never share one node
        self.gait += 1
        claimed: set[str] = set()
        taken: list[float] = []
        for lg in self.legs:
            lg.update(self.bx, self.by, self.ba, nodes, self.hip_reach, claimed, taken)

    def draw(self, d):
        # hips in world space
        hips = []
        for lg in self.legs:
            a = self.ba + lg.rest_angle * lg.side
            hips.append((self.bx + math.cos(a) * 34, self.by + math.sin(a) * 34))

        # legs behind the body
        for lg, hip in zip(self.legs, hips):
            lg.draw(d, hip)

        # abdomen (rear) and cephalothorax (front), oriented to heading
        ca, sa = math.cos(self.ba), math.sin(self.ba)
        def P(fx, fy):
            return (self.bx + ca * fx - sa * fy, self.by + sa * fx + ca * fy)

        # abdomen: armored faceted plate (rear)
        poly(d, [P(-120, 0), P(-96, -46), P(-28, -40), P(-6, 0),
                 P(-28, 40), P(-96, 46)], fill=NAVY, outline=CYAN, width=3)
        d.line([P(-92, -22), P(-30, -19)], fill=CYAN_D, width=2)
        d.line([P(-92, 22), P(-30, 19)], fill=CYAN_D, width=2)
        # energy core
        c0 = P(-58, 0)
        d.polygon([(c0[0], c0[1] - 15), (c0[0] + 15, c0[1]),
                   (c0[0], c0[1] + 15), (c0[0] - 15, c0[1])], fill=CYAN)
        d.polygon([(c0[0], c0[1] - 7), (c0[0] + 7, c0[1]),
                   (c0[0], c0[1] + 7), (c0[0] - 7, c0[1])], fill=(6, 14, 26))

        # cephalothorax: angular wedge (front)
        poly(d, [P(62, 0), P(40, -34), P(-12, -32), P(-26, 0),
                 P(-12, 32), P(40, 34)], fill=(10, 26, 58), outline=CYAN, width=3)
        # eyes: two square cyan LEDs, the house style — slightly larger so they read
        for ey in (-15, 3):
            e = P(48, ey)
            d.rectangle((e[0] - 6, e[1] - 5, e[0] + 6, e[1] + 5), fill=(6, 14, 26),
                        outline=CYAN_L, width=1)
            d.rectangle((e[0] - 4, e[1] - 3, e[0] + 4, e[1] + 3), fill=WHITE)
        # pedipalps: hard angular spurs
        for s in (-1, 1):
            poly(d, [P(54, 12 * s), P(88, 20 * s), P(88, 28 * s), P(54, 22 * s)],
                 fill=CYAN_D)


def load_nodes(events_path):
    evs = [json.loads(l) for l in open(events_path)]
    pages = [e for e in evs if e["kind"] == "page"]
    order, seen = [], set()
    for e in pages:
        if e["url"] not in seen:
            seen.add(e["url"])
            order.append(e["url"])
    return order, pages


def layout(order, x0, y0, x1, y1, pad=120):
    """Phyllotaxis, computed once from ALL nodes so nothing shifts."""
    n = max(len(order), 1)
    cx, cy = (x0 + x1) / 2, (y0 + y1) / 2
    rx, ry = (x1 - x0) / 2 - pad, (y1 - y0) / 2 - pad
    pos = {}
    for i, u in enumerate(order):
        r = math.sqrt((i + 0.5) / n)
        th = i * 2.399963229728653
        pos[u] = (cx + r * rx * math.cos(th), cy + r * ry * math.sin(th))
    return pos


def frame(nodes, pos, order, visited, spider, title, sub, badge):
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    for x in range(0, W, 40):
        d.line((x, 0, x, H), fill=(13, 24, 50), width=1)
    for y in range(0, H, 40):
        d.line((0, y, W, y), fill=(13, 24, 50), width=1)

    d.rectangle((36, 30, 54, 48), fill=CYAN)
    d.text((66, 24), title, font=ImageFont.truetype(MONO_B, 30), fill=CYAN)
    d.text((36, 62), sub, font=ImageFont.truetype(MONO, 17), fill=GRAY)
    if badge:
        f = ImageFont.truetype(MONO_B, 20)
        tb = d.textbbox((0, 0), badge, font=f)
        bw = tb[2] - tb[0] + 34
        d.rounded_rectangle((W - 36 - bw, 26, W - 36, 66), radius=8, fill=GREEN)
        d.text((W - 36 - bw + 17, 36), badge, font=f, fill=(6, 10, 18))

    # edges: very faint web between nearby nodes the spider has walked
    idx = {u: i for i, u in enumerate(order)}
    vis = [(u, pos[u], idx[u]) for u in order if u in visited and u in pos]
    for u, pu, iu in vis:
        for v, pv, iv in vis:
            if u != v and abs(iu - iv) <= 3:
                d.line((pu[0], pu[1], pv[0], pv[1]), fill=(13, 28, 50), width=1)

    # nodes
    for u in order:
        x, y = pos[u]
        if u in visited:
            d.ellipse((x - 7, y - 7, x + 7, y + 7), outline=CYAN_D, width=2)
            d.ellipse((x - 3, y - 3, x + 3, y + 3), fill=CYAN)
        else:
            d.rectangle((x - 2, y - 2, x + 2, y + 2), fill=(42, 52, 72))

    # vignette only the spider's bounding box (a full-canvas composite per
    # frame is needlessly slow over 400 frames), so the silhouette reads
    hx0, hy0 = int(clamp(spider.bx - 315, 0, W)), int(clamp(spider.by - 270, 0, H))
    hx1, hy1 = int(clamp(spider.bx + 315, 0, W)), int(clamp(spider.by + 270, 0, H))
    if hx1 > hx0 and hy1 > hy0:
        reg = img.crop((hx0, hy0, hx1, hy1))
        msk = Image.new("L", reg.size, 0)
        ImageDraw.Draw(msk).ellipse((0, 0, reg.size[0], reg.size[1]), fill=165)
        reg = Image.composite(Image.new("RGB", reg.size, (5, 8, 15)), reg, msk)
        img.paste(reg, (hx0, hy0))
        d = ImageDraw.Draw(img)

    spider.draw(d)

    # label the node being gripped (gripping stores the URL, not the point)
    gripped = [lg.gripping for lg in spider.legs if lg.gripping]
    if gripped and gripped[0] in pos:
        u = gripped[0]
        gx, gy = pos[u]
        lbl = urlsplit(u).path or "/"
        if len(lbl) > 24:
            lbl = lbl[:23] + "…"
        f = ImageFont.truetype(MONO, 16)
        tb = d.textbbox((0, 0), lbl, font=f)
        lw, lh = tb[2] - tb[0], tb[3] - tb[1]
        lx, ly = gx + 14, gy - 34
        # backing plate so the label never collides with the body or legs
        d.rounded_rectangle((lx - 7, ly - 5, lx + lw + 7, ly + lh + 7), radius=5,
                            fill=(4, 9, 18), outline=CYAN_D, width=1)
        d.text((lx, ly), lbl, font=f, fill=CYAN_L)
    return img


def build(events_path):
    order, pages = load_nodes(events_path)
    pos = layout(order, 0, 96, W, H)
    nodes = {u: pos[u] for u in order}
    spider = Spider()
    spider.place(pos[order[0]][0], pos[order[0]][1], 0.0)

    os.makedirs(FRAMES, exist_ok=True)
    scenes = []

    def save(img, name):
        p = os.path.join(FRAMES, name)
        img.save(p)
        return p

    # intro
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    for x in range(0, W, 40):
        d.line((x, 0, x, H), fill=(13, 24, 50), width=1)
    for y in range(0, H, 40):
        d.line((0, y, W, y), fill=(13, 24, 50), width=1)
    d.rectangle((90, 288, 112, 310), fill=CYAN)
    d.text((132, 274), "THE CRAWLER", font=ImageFont.truetype(MONO_B, 76), fill=CYAN)
    d.text((94, 392), "six legs, two-link IK, solved fresh every frame",
           font=ImageFont.truetype(MONO, 25), fill=WHITE)
    d.text((94, 436), "each foot grabs the nearest real page it can reach",
           font=ImageFont.truetype(MONO, 25), fill=GRAY)
    d.text((94, 480), "no sprite sheets — all of it is math",
           font=ImageFont.truetype(MONO, 25), fill=AMBER)
    scenes.append((save(img, "s_intro.png"), 3.4))

    visited = set()
    idx = 0
    nframes = 0
    # walk the tour: aim at each node in crawl order
    target_i = 0
    speed = 7.5
    while target_i < len(order) and nframes < 400:
        tgt = pos[order[target_i]]
        for _ in range(3):
            dx, dy = tgt[0] - spider.bx, tgt[1] - spider.by
            dist = math.hypot(dx, dy)
            if dist < 26:
                target_i += 1
                break
            want = math.atan2(dy, dx)
            diff = (want - spider.ba + math.pi) % (2 * math.pi) - math.pi
            spider.ba += clamp(diff, -0.06, 0.06)          # smooth turn
            step = min(speed, dist)
            # keep the body far enough from the edges that legs stay in frame
            spider.bx = clamp(spider.bx + math.cos(spider.ba) * step, 340, W - 340)
            spider.by = clamp(spider.by + math.sin(spider.ba) * step, 330, H - 235)
            spider.update(nodes)
            visited.add(order[max(0, target_i - 1)])
            visited.add(order[target_i])
            nframes += 1
            done = min(target_i + 1, len(order))
            img = frame(nodes, pos, order, visited, spider, "D0XED ARCHITECT",
                        "crawling the site graph — every node is a real page",
                        f"{done}/{len(order)} PAGES")
            scenes.append((save(img, f"w{nframes:04d}.png"), 1.0 / 10))
            if nframes >= 400:
                break

    # hold on the finished web
    img = frame(nodes, pos, order, set(order), spider, "D0XED ARCHITECT",
                "crawl complete — the web it built", f"{len(order)}/{len(order)} PAGES")
    scenes.append((save(img, "s_end.png"), 4.0))
    return scenes


def encode(out_path, scenes):
    seq = os.path.join(FRAMES, "seq")
    shutil.rmtree(seq, ignore_errors=True)
    os.makedirs(seq, exist_ok=True)
    n = 0
    for png, dur in scenes:
        for _ in range(max(1, int(round(dur * FPS)))):
            n += 1
            shutil.copyfile(png, os.path.join(seq, f"f{n:05d}.png"))
    r = subprocess.run(
        ["ffmpeg", "-y", "-framerate", str(FPS), "-i", os.path.join(seq, "f%05d.png"),
         "-c:v", "libx264", "-preset", "veryfast", "-crf", "20", "-pix_fmt", "yuv420p",
         "-movflags", "+faststart", out_path], capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit(r.stderr[-2000:])
    shutil.rmtree(seq, ignore_errors=True)
    return out_path


if __name__ == "__main__":
    ev = sys.argv[1] if len(sys.argv) > 1 else os.path.join(OUTDIR, "crawl-events.jsonl")
    out = sys.argv[2] if len(sys.argv) > 2 else os.path.join(OUTDIR, "d0xed-spider.mp4")
    sc = build(ev)
    encode(out, sc)
    print(f"frames: {len(sc)}  ({sum(d for _, d in sc):.1f}s)")
    print(f"video : {out}")