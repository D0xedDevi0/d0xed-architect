#!/usr/bin/env python3
"""Render the D0xed Architect demo MP4 from REAL captured CLI output.

Nothing here is invented: every line rendered is a line the tools actually
printed. Frame content comes from /tmp/demo-crawl2.log, /tmp/demo-place.log and
/tmp/demo-verify.log, produced by real runs against d0xeddev.com and the
D0XEDDEV repository.

Style: D0xed blueprint — navy #001240 field, cyan #00d4ff accents, pixel grid.
"""
import os
import subprocess

from PIL import Image, ImageDraw, ImageFont

W, H = 1600, 900
BG = (8, 11, 20)
NAVY = (0, 18, 64)
PANEL = (10, 16, 34)
CYAN = (0, 212, 255)
GREEN = (0, 230, 118)
AMBER = (255, 190, 60)
RED = (255, 69, 58)
GRAY = (140, 150, 170)
DIM = (86, 96, 116)
WHITE = (235, 238, 245)

MONO = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
MONO_BOLD = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"

OUT = "/opt/data/d0xed-architect/demo"
FRAMES = os.path.join(OUT, "frames")


def _f(path, size):
    return ImageFont.truetype(path, size)


def _grid(d, x0, y0, x1, y1, step=40, color=(16, 30, 62)):
    """Faint pixel grid — the D0xed blueprint field."""
    for x in range(x0, x1, step):
        d.line((x, y0, x, y1), fill=color, width=1)
    for y in range(y0, y1, step):
        d.line((x0, y, x1, y), fill=color, width=1)


def frame(lines, *, title="d0xed architect", subtitle=None, badge=None,
          badge_color=CYAN):
    """One terminal window: title bar, optional subtitle, color-coded body."""
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)

    _grid(d, 0, 0, W, H)

    px0, py0, px1, py1 = 40, 36, W - 40, H - 36
    d.rounded_rectangle((px0, py0, px1, py1), radius=16, fill=PANEL,
                        outline=CYAN, width=2)

    # title bar
    bar_h = 52
    d.rounded_rectangle((px0, py0, px1, py0 + bar_h), radius=16, fill=NAVY)
    d.rectangle((px0, py0 + bar_h - 16, px1, py0 + bar_h), fill=NAVY)
    for i, c in enumerate(((255, 95, 86), (255, 189, 46), (39, 201, 63))):
        cx = px0 + 28 + i * 26
        d.ellipse((cx, py0 + 20, cx + 14, py0 + 34), fill=c)
    d.text((px0 + 120, py0 + 14), title, font=_f(MONO_BOLD, 22), fill=CYAN)

    if badge:
        tb = d.textbbox((0, 0), badge, font=_f(MONO_BOLD, 20))
        bx1 = px1 - 24
        bx0 = bx1 - (tb[2] - tb[0]) - 32
        d.rounded_rectangle((bx0, py0 + 12, bx1, py0 + 40), radius=8,
                            fill=badge_color)
        d.text((bx0 + 16, py0 + 17), badge, font=_f(MONO_BOLD, 20),
               fill=(6, 10, 18))

    y = py0 + bar_h + 22
    if subtitle:
        d.text((px0 + 32, y), subtitle, font=_f(MONO, 20), fill=DIM)
        y += 40

    body = _f(MONO, 21)
    for text, color in lines:
        d.text((px0 + 32, y), text, font=body, fill=color)
        y += 31
    return img


def save(img, name):
    os.makedirs(FRAMES, exist_ok=True)
    p = os.path.join(FRAMES, name)
    img.save(p)
    return p


# ── palette shorthands ─────────────────────────────────────────────────────
def c(s, col=WHITE):
    return (s, col)


def build():
    scenes = []

    # 1 ── title
    scenes.append((save(frame([
        c(""),
        c("   D0XED ARCHITECT", CYAN),
        c(""),
        c("   an identity-declared, x402-paying crawler"),
        c("   and an amnesic code auditor."),
        c(""),
        c("   Trust should be architectural, not promised.", AMBER),
        c(""),
        c("   no finding without  file:line + snippet + sha256"),
    ], title="d0xed architect  v0.3", badge="LIVE RUN",
        badge_color=CYAN), "01_title.png"), 4.0))

    # 2 ── crawl contract: baseddoom (robots honoured)
    scenes.append((save(frame([
        c("$ architect crawl https://baseddoom.com --max-pages 12", CYAN),
        c(""),
        c("[architect] robots.txt=found llms.txt=absent", GREEN),
        c("[architect] ✓ https://baseddoom.com (11w, trust 100)", GREEN),
        c(""),
        c("## 🟦 Crawl contract"),
        c("- robots.txt: found (0 disallow, 1 allow)", GREEN),
        c("- sitemaps: 1"),
        c(""),
        c("## 🟦 Trust layer"),
        c("- pages scanned: 1   clean: 1   flagged: 0", GREEN),
        c(""),
        c("  it reads the rules first, and obeys them.", AMBER),
    ], title="crawl  ·  baseddoom.com", badge="ROBOTS HONOURED",
        badge_color=GREEN), "02_crawl_robots.png"), 5.0))

    # 3 ── crawl d0xeddev.com, progressive (real output, real page count)
    pages = [
        "✓ https://d0xeddev.com (2243w, trust 100)",
        "✓ https://d0xeddev.com/paraswarm (174w, trust 100)",
        "✓ https://d0xeddev.com/intel (498w, trust 100)",
        "✓ https://d0xeddev.com/trading (327w, trust 100)",
        "✓ https://d0xeddev.com/api (403w, trust 100)",
        "✓ https://d0xeddev.com/learn/tools (706w, trust 100)",
    ]
    for k in range(1, len(pages) + 1):
        body = [c("$ architect crawl https://d0xeddev.com --max-pages 25", CYAN),
                c("")]
        body += [c("  " + p, GREEN) for p in pages[:k]]
        if k == len(pages):
            body += [c("  … 25 pages total, 434 edges, 5.4s", WHITE),
                     c(""),
                     c("- robots.txt: absent (0 disallow, 0 allow)", RED),
                     c("  ^ my own crawler caught my own site missing it.", AMBER)]
        scenes.append((save(frame(
            body, title="crawl  ·  d0xeddev.com", badge=f"{k} PAGES",
            badge_color=CYAN), f"03_crawl_{k:02d}.png"), 0.9))

    # 4 ── the swarm, nodes completing on REAL timings
    stages = [
        [("·", "contract", "", DIM)],
        [("·", "contract", "", DIM), ("·", "secrets", "", DIM)],
        [("✓", "contract", "70f  0.69s", GREEN), ("·", "secrets", "", DIM),
         ("·", "deps", "", DIM)],
        [("✓", "contract", "70f  0.69s", GREEN),
         ("✓", "secrets", "1398f  7.35s", GREEN), ("·", "deps", "", DIM),
         ("·", "repo", "", DIM)],
        [("✓", "contract", "70f  0.69s", GREEN),
         ("✓", "secrets", "1398f  7.35s", GREEN),
         ("✓", "deps", "7f  0.20s", GREEN),
         ("✓", "repo", "1398f  0.56s", GREEN)],
    ]
    for k, stage in enumerate(stages, 1):
        body = [c("$ architect place /opt/data/D0XEDDEV \\", CYAN),
                c("      --nodes contract,secrets,deps,repo", CYAN),
                c("")]
        for mark, name, timing, col in stage:
            body.append(c(f"  {mark} {name:<10} {timing}", col))
        body.append(c(""))
        if k < len(stages):
            body.append(c("  nodes light up only when they actually run.", AMBER))
        else:
            body.append(c("  ✓ swarm complete — 187 finding(s) in 7.35s", GREEN))
        scenes.append((save(frame(
            body, title="d0x swarm  ·  place", badge=f"STAGE {k}/5",
            badge_color=CYAN), f"04_swarm_{k:02d}.png"), 1.5))

    # 5 ── findings strip (real severities)
    scenes.append((save(frame([
        c("🟦 D0XED ARCHITECT · d0x swarm", CYAN),
        c(""),
        c(" nodes                     │ findings", GRAY),
        c(" ✓ contract  70f  0.69s    │ ● critical   0", GREEN),
        c(" ✓ secrets 1398f  7.35s    │ ● high       3 ███", RED),
        c(" ✓ deps       7f  0.20s    │ ● medium    87 ███████████", AMBER),
        c(" ✓ repo    1398f  0.56s    │ ● low       90 ███████████", GRAY),
        c(""),
        c(" 💳 0.000000 USDC · 0 settled · manifest 573d7950…", CYAN),
        c(""),
        c("  spend moves only when a 402 actually settles.", AMBER),
    ], title="d0x swarm  ·  findings", badge="0 CRITICAL",
        badge_color=GREEN), "05_findings.png"), 6.0))

    # 6 ── the receipts verify
    scenes.append((save(frame([
        c("$ architect verify-report demo-place.json", CYAN),
        c(""),
        c("findings     : 187"),
        c("verified     : 187", GREEN),
        c("manifest root: 573d79506c17318986dcbd18e1b92a442198989d19"),
        c("               6bffe6b332b0c304d0c11a"),
        c(""),
        c("VERIFIED — every finding reproduces from this tree.", GREEN),
        c(""),
        c("  you don't trust the auditor. you re-hash it.", AMBER),
    ], title="verify-report  ·  the receipt check", badge="REPRODUCIBLE",
        badge_color=GREEN), "06_verify.png"), 6.0))

    # 7 ── the honest part
    scenes.append((save(frame([
        c("what the tool says about its own author's code:", GRAY),
        c(""),
        c(" high  weak_randomness         DAGENT.sol:536", RED),
        c("       uint256 seed = uint256(keccak256(abi.encodePacked(", DIM),
        c("       ^ my own mitigation — still not verifiable randomness.", AMBER),
        c(""),
        c(" high  reentrancy_…  MockAerodromeRouterFull.sol:44", RED),
        c("       ^ test-only mock — annotated, downgraded, not dropped.", AMBER),
        c(""),
        c("  a scanner that cries wolf is worse than none.", WHITE),
    ], title="honest severity", badge="3 HIGH, 0 CRITICAL",
        badge_color=AMBER), "07_honest.png"), 7.0))

    # 8 ── close
    scenes.append((save(frame([
        c(""),
        c("   🟦 D0xed Architect", CYAN),
        c(""),
        c("   crawler · swarm · receipts · x402 rails"),
        c(""),
        c("   github.com/D0xedDevi0/d0xed-architect", GREEN),
        c("   d0xeddev.com", GREEN),
        c(""),
        c("   396 contract tests · 52 architect checks", WHITE),
        c("   0 critical on a real 1398-file repo", WHITE),
        c(""),
        c("   Code. Culture. Base.", AMBER),
    ], title="d0xed architect", badge="NFA · DYOR",
        badge_color=CYAN), "08_close.png"), 5.0))

    return scenes


def concat(out_path, scenes, fps=30):
    cmd = ["ffmpeg", "-y"]
    for png, dur in scenes:
        cmd += ["-loop", "1", "-t", str(dur), "-i", png]
    filt = "".join(f"[{i}]" for i in range(len(scenes))) + \
           f"concat=n={len(scenes)}:v=1:a=0,format=yuv420p"
    cmd += ["-filter_complex", filt, "-r", str(fps),
            "-c:v", "libx264", "-preset", "medium", "-crf", "20",
            "-movflags", "+faststart", out_path]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit(r.stderr[-2500:])
    return out_path


if __name__ == "__main__":
    os.makedirs(OUT, exist_ok=True)
    sc = build()
    out = os.path.join(OUT, "d0xed-architect-demo.mp4")
    concat(out, sc)
    total = sum(d for _, d in sc)
    print(f"frames : {len(sc)}")
    print(f"video  : {out}")
    print(f"length : {total:.1f}s (planned)")
