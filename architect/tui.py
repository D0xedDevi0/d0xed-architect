"""Live swarm view — the visual layer, backed by real events only.

Design rule: every element on screen maps to an event that actually happened.
The spend meter moves when a 402 settles and never otherwise. Node status is
derived from node_start/node_done/node_error, not a timer. If a node has not
reported, it shows as pending, because that is what is true.

`render()` is a pure function of the view state, which means the layout is
testable without a terminal and cannot drift from the event stream.

Non-TTY behaviour: no escape codes, no cursor games — the event log and a final
frame, so piping to a file or a CI log still produces something honest.
"""

from __future__ import annotations

import os
import sys
import threading
import time
import unicodedata

from . import events as _events

C = {
    "reset": "\x1b[0m", "dim": "\x1b[2m", "bold": "\x1b[1m",
    "red": "\x1b[31m", "green": "\x1b[32m", "yellow": "\x1b[33m",
    "blue": "\x1b[34m", "magenta": "\x1b[35m", "cyan": "\x1b[36m",
}

SEV_STYLE = {
    "critical": ("red", "●"), "high": ("magenta", "●"), "medium": ("yellow", "●"),
    "low": ("blue", "●"), "info": ("dim", "·"),
}
SEV_ORDER = ["critical", "high", "medium", "low", "info"]

NODE_MARK = {"pending": ("dim", "·"), "running": ("cyan", "⟳"),
             "done": ("green", "✓"), "error": ("red", "✗")}


def dw(s: str) -> int:
    """Display width — wide/emoji chars occupy two cells."""
    n = 0
    for ch in s:
        if unicodedata.combining(ch):
            continue
        n += 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1
    return n


def pad(s: str, width: int) -> str:
    return s + " " * max(0, width - dw(s))


def trunc(s: str, width: int) -> str:
    if dw(s) <= width:
        return s
    out, n = "", 0
    for ch in s:
        w = 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1
        if n + w > width - 1:
            break
        out += ch
        n += w
    return out + "…"


class SwarmView:
    """Holds live swarm state; consumes events; renders frames."""

    def __init__(self, bus: _events.EventBus, width: int = 78,
                 color: bool | None = None, max_events: int = 8):
        self.bus = bus
        self.width = width
        self.max_events = max_events
        self.color = _auto_color() if color is None else color
        self.nodes: dict[str, dict] = {}
        self.counts = {s: 0 for s in SEV_ORDER}
        self.events: list[str] = []
        self.spend = 0.0
        self.cap = 0.0
        self.settled = 0
        self.manifest_root = ""
        self.started = time.time()
        self.finished = False
        self._lock = threading.Lock()

    # -- event intake ------------------------------------------------------
    def consume(self, ev: _events.Event) -> None:
        with self._lock:
            if ev.kind == _events.SWARM_START:
                for n in ev.payload.get("nodes", []):
                    self.nodes[n] = {"status": "pending", "findings": 0,
                                     "files": 0, "duration": 0.0}
            elif ev.kind == _events.NODE_START:
                self.nodes.setdefault(ev.node, {}).update(status="running")
            elif ev.kind == _events.NODE_DONE:
                d = {"status": "done", "findings": ev.payload.get("findings", 0),
                     "files": ev.payload.get("files", 0),
                     "duration": ev.payload.get("duration", 0.0)}
                for k in ("modules", "baseline", "breaking", "notable", "info"):
                    if k in ev.payload:
                        d[k] = ev.payload[k]
                self.nodes.setdefault(ev.node, {}).update(d)
            elif ev.kind == _events.NODE_ERROR:
                self.nodes.setdefault(ev.node, {}).update(status="error")
            elif ev.kind == _events.FINDING:
                sev = ev.payload.get("severity", "info")
                self.counts[sev] = self.counts.get(sev, 0) + 1
            elif ev.kind == _events.PAYMENT:
                self.spend += float(ev.payload.get("amount_usdc", 0.0))
                self.settled += 1
            elif ev.kind == _events.SWARM_DONE:
                self.manifest_root = ev.payload.get("manifest_root", "")
                self.finished = True

            line = f"{_clock(ev.t - self.started)} {ev.text()}"
            self.events.append(line)
            if len(self.events) > 200:
                del self.events[:100]

    def set_cap(self, cap: float) -> None:
        self.cap = cap

    # -- rendering ---------------------------------------------------------
    def _c(self, color: str, text: str) -> str:
        return f"{C[color]}{text}{C['reset']}" if self.color else text

    def render(self) -> list[str]:
        with self._lock:
            nodes = dict(self.nodes)
            counts = dict(self.counts)
            events = list(self.events)
            spend, cap, settled = self.spend, self.cap, self.settled
            root, finished = self.manifest_root, self.finished

        w = self.width
        out = []

        title = "🟦 D0XED ARCHITECT · d0x swarm "
        out.append(self._c("cyan", title) + self._c("dim", "─" * max(0, w - dw(title))))

        # -- two columns: nodes | findings
        left_w = max(30, w // 2 - 1)
        right_w = w - left_w - 1
        hdr_l = pad(" nodes", left_w)
        hdr_r = pad(" findings", right_w)
        out.append(self._c("bold", hdr_l) + self._c("dim", "│") + self._c("bold", hdr_r))

        left_lines, right_lines = [], []
        for name, st in nodes.items():
            col, mark = NODE_MARK.get(st.get("status", "pending"), ("dim", "·"))
            label = f" {self._c(col, mark)} {pad(trunc(name, 12), 12)}"
            if (name == "sentinel" and st.get("status") == "done"
                    and any(k in st for k in ("breaking", "notable", "info"))):
                b, n, i = (st.get("breaking", 0), st.get("notable", 0),
                           st.get("info", 0))
                tail = f"{b}B/{n}N/{i}I drift"
            elif (name == "sentinel" and st.get("status") == "done"
                    and st.get("baseline") == "none"):
                tail = self._c("dim", "no baseline")
            else:
                tail = (f"{st.get('files', 0):>4}f {st.get('duration', 0):>5.2f}s"
                        if st.get("status") in ("done", "running")
                        else self._c("dim", "pending"))
            left_lines.append(label + self._c("dim", tail))

        total = sum(counts.values())
        for sev in SEV_ORDER:
            n = counts.get(sev, 0)
            col, mark = SEV_STYLE[sev]
            bar = "█" * n if n else self._c("dim", "·")
            right_lines.append(
                f" {self._c(col, mark)} {pad(sev, 9)} {n:>4} "
                + (self._c(col, trunc(bar, 12)) if n else bar))

        rows = max(len(left_lines), len(right_lines))
        for i in range(rows):
            l = left_lines[i] if i < len(left_lines) else ""
            r = right_lines[i] if i < len(right_lines) else ""
            out.append(pad(l, left_w) + self._c("dim", "│") + pad(r, right_w))

        out.append(self._c("dim", "─" * w))

        # -- event stream
        recent = events[-self.max_events:]
        out.append(self._c("bold", " events"))
        if not recent:
            out.append(self._c("dim", "  waiting for the first node…"))
        for line in recent:
            out.append(" " + trunc(line, w - 2))

        out.append(self._c("dim", "─" * w))
        meter = f"💳 {spend:.6f} / {cap:.6f} USDC · {settled} settled"
        if root:
            meter += f" · manifest {root[:12]}…"
        elif finished:
            meter += " · manifest —"
        out.append(self._c("green" if finished else "dim", " " + trunc(meter, w - 2)))
        return out

    def frame(self) -> str:
        return "\n".join(self.render())

    def draw(self, clear: bool = True) -> None:
        if clear:
            sys.stdout.write("\x1b[H\x1b[2J")
        sys.stdout.write(self.frame() + "\n")
        sys.stdout.flush()


def _clock(seconds: float) -> str:
    seconds = max(0.0, seconds)
    return f"{int(seconds // 60):02d}:{seconds % 60:05.2f}"


def _auto_color() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


def run_with_view(root: str, node_names, bus: _events.EventBus, cap: float = 0.0,
                  width: int = 78, color: bool | None = None,
                  interval: float = 0.08, stream=None) -> dict:
    """Run the swarm with the live view (TTY) or an event log (non-TTY)."""
    from .nodes import run_swarm

    stream = stream or sys.stdout
    view = SwarmView(bus, width=width, color=color)
    view.set_cap(cap)
    bus.subscribe(view.consume)

    if not (color if color is not None else _auto_color()):
        echo = _events.EventBus(echo=lambda ev: stream.write("  " + ev.text() + "\n"))
        bus._echo = echo._echo  # stream events in non-tty mode
        result = run_swarm(root, node_names, bus)
        stream.write("\n" + view.frame() + "\n")
        return result

    box: dict = {}

    def work():
        box["result"] = run_swarm(root, node_names, bus)

    th = threading.Thread(target=work, daemon=True)
    th.start()
    try:
        while th.is_alive():
            view.draw()
            time.sleep(interval)
        view.draw()
    except KeyboardInterrupt:
        stream.write("\n  interrupted — swarm stopped, nothing was written to disk\n")
        th.join(timeout=2)
        raise SystemExit(130)
    return box.get("result", {})