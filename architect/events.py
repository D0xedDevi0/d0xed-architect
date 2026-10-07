"""Event bus — every visual element in the TUI maps to a real event.

The view is not decoration and it is not a spinner. If a node lights up, a node
ran. If the spend meter moves, a payment settled. A progress bar that animates
while nothing happens is a lie, and this tool does not tell lies.

Keeping the bus separate from the renderer means the swarm is testable without a
terminal: assert on the event stream, then assert the frames agree with it.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field

# event kinds
SWARM_START = "swarm_start"
NODE_START = "node_start"
NODE_DONE = "node_done"
NODE_ERROR = "node_error"
FINDING = "finding"
PAYMENT = "payment"
NOTE = "note"
SWARM_DONE = "swarm_done"


@dataclass
class Event:
    kind: str
    node: str = ""
    payload: dict = field(default_factory=dict)
    t: float = field(default_factory=time.time)

    def text(self) -> str:
        p = self.payload
        if self.kind == NODE_START:
            return f"⟳ {self.node} started"
        if self.kind == NODE_DONE:
            return (f"✓ {self.node} done — {p.get('findings', 0)} finding(s), "
                    f"{p.get('files', 0)} file(s), {p.get('duration', 0):.2f}s")
        if self.kind == NODE_ERROR:
            return f"✗ {self.node} failed — {p.get('error', '')}"
        if self.kind == FINDING:
            return f"⚑ {p.get('severity', '?')} {p.get('rule', '')} {p.get('where', '')}"
        if self.kind == PAYMENT:
            return f"💳 settled {p.get('amount_usdc', 0):.6f} USDC → {p.get('payTo', '')}"
        if self.kind == SWARM_START:
            return f"🕸️ swarm starting — nodes: {', '.join(p.get('nodes', []))}"
        if self.kind == SWARM_DONE:
            return (f"✓ swarm complete — {p.get('findings', 0)} finding(s) in "
                    f"{p.get('duration', 0):.2f}s")
        return p.get("msg", self.kind)


class EventBus:
    """Thread-safe append-only event log with subscribers."""

    def __init__(self, echo=None):
        self._lock = threading.Lock()
        self.history: list[Event] = []
        self._subs: list = []
        self._echo = echo

    def subscribe(self, fn):
        with self._lock:
            self._subs.append(fn)

    def emit(self, kind: str, node: str = "", **payload) -> Event:
        ev = Event(kind=kind, node=node, payload=payload)
        with self._lock:
            self.history.append(ev)
            subs = list(self._subs)
        if self._echo is not None:
            self._echo(ev)
        for fn in subs:
            try:
                fn(ev)
            except Exception:  # noqa: BLE001 - a bad subscriber must not kill the run
                pass
        return ev

    def of(self, *kinds: str) -> list[Event]:
        with self._lock:
            return [e for e in self.history if e.kind in kinds]

    def findings(self) -> list[Event]:
        return self.of(FINDING)

    def payments(self) -> list[Event]:
        return self.of(PAYMENT)