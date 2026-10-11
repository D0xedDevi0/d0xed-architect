"""Bounded command parsing.

The allowed set is a single tuple so a handler cannot exist without a
registration (see the bot dispatch-table test). Commands are /start /help
(no arg), /audit /debug /map (one URL arg), and /doctor (no arg). Anything
else — unknown commands, plain text, oversized messages, wrong arity — is a
`reject` and never reaches a handler.
"""
from __future__ import annotations

from dataclasses import dataclass

COMMANDS = ("/start", "/help", "/audit", "/debug", "/map", "/doctor")

_NO_ARG = ("start", "help", "doctor")
_ONE_ARG = ("audit", "debug", "map")


@dataclass(frozen=True)
class Command:
    kind: str              # "start" | "help" | "audit" | "debug" | "map" | "doctor" | "reject"
    arg: str | None = None
    error: str | None = None


def parse_command(text: str | None, max_len: int) -> Command:
    if not text:
        return Command("reject", error="empty message")
    if len(text) > max_len:
        return Command("reject", error="message too long")
    s = text.strip()
    if not s.startswith("/"):
        return Command("reject", error="not a command")
    parts = s.split(None, 1)
    name = parts[0].split("@", 1)[0]        # strip a /cmd@BotName mention
    rest = parts[1].strip() if len(parts) > 1 else ""
    if name not in COMMANDS:
        return Command("reject", error="unknown command")
    kind = name[1:]
    if kind in _NO_ARG:
        return Command(kind)
    # /audit /debug /map require exactly one argument
    if not rest:
        return Command("reject", error=f"usage: /{kind} <url>")
    if len(rest.split()) != 1:
        return Command("reject", error=f"usage: /{kind} <url>")
    return Command(kind, arg=rest)
