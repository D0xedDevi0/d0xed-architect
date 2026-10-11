"""Bounded command parsing. Only /start, /help and /audit exist.

Anything else — unknown commands, plain text, oversized messages, extra
arguments — is a `reject` and never reaches a handler. The allowed set is a
single tuple so a handler cannot exist without a registration (see the bot
dispatch table test).
"""
from __future__ import annotations

from dataclasses import dataclass

COMMANDS = ("/start", "/help", "/audit")


@dataclass(frozen=True)
class Command:
    kind: str              # "start" | "help" | "audit" | "reject"
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
    if kind in ("start", "help"):
        return Command(kind)
    # /audit requires exactly one argument
    if not rest:
        return Command("reject", error="usage: /audit <github-url>")
    if len(rest.split()) != 1:
        return Command("reject", error="usage: /audit <github-url>")
    return Command("audit", arg=rest)
