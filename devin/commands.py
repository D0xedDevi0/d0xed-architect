"""Bounded command parsing.

The allowed set is a single tuple so a handler cannot exist without a
registration (see the bot dispatch-table test). Commands are:

  /start [payload]   /help   /spellbook   /lore   /doctor   /link
  /audit <url>  /debug <url>  /map <url>  /sitemap <url>
  /crawl <url> [depth]   /bundle <github-url>   /sigil <words>

Anything else — unknown commands, plain text, oversized messages, wrong arity,
an out-of-range crawl depth — is a `reject` and never reaches a handler.

`/start` accepts an optional deep-link payload (Telegram sends
`/start <payload>` for `https://t.me/<bot>?start=<payload>`); the payload is
carried as `arg` so the welcome can be tailored without a second command.
"""
from __future__ import annotations

from dataclasses import dataclass

COMMANDS = ("/start", "/help", "/spellbook", "/lore", "/audit", "/debug",
            "/map", "/crawl", "/sitemap", "/link", "/bundle", "/sigil",
            "/doctor", "/judge")

_NO_ARG = ("help", "spellbook", "lore", "doctor", "link")
_ONE_ARG = ("audit", "debug", "map", "sitemap", "bundle")
_DEPTH_ARG = ("crawl",)

# /sigil takes free text (it hashes words), so it has its own bound instead of
# the single-token rule the URL commands use.
_SIGIL_MAX = 200

# A crawl deeper than this stops being a site map and starts being a burden on
# someone else's server; the handler also enforces this.
MIN_DEPTH, MAX_DEPTH = 1, 4

_PAYLOAD_MAX = 64


@dataclass(frozen=True)
class Command:
    kind: str              # "start" | "help" | ... | "reject"
    arg: str | None = None
    error: str | None = None
    depth: int | None = None
    objective: str | None = None


def _clean_payload(rest: str) -> str | None:
    """Deep-link payloads are untrusted input: keep them short, printable, and
    alphanumeric-ish, and never echo anything that looks like a token."""
    p = rest.strip()
    if not p:
        return None
    p = p.split()[0]
    if len(p) > _PAYLOAD_MAX:
        return None
    if not all(c.isalnum() or c in "-_" for c in p):
        return None
    return p


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
    if kind == "judge":
        url, separator, objective = rest.partition("|")
        url, objective = url.strip(), objective.strip()
        try:
            from architect.decision_types import public_url
            from architect.semantic import safe_text
            public_url(url)
            if not separator or not objective or len(objective.encode()) > 1024 or not safe_text(objective):
                raise ValueError("judge")
        except ValueError:
            return Command("reject", error="usage: /judge <public-url> | <objective>")
        return Command("judge", arg=url, objective=objective)
    if kind == "start":
        return Command("start", arg=_clean_payload(rest))
    if kind in _NO_ARG:
        return Command(kind)
    if kind in _ONE_ARG:
        if not rest:
            return Command("reject", error=f"usage: /{kind} <url>")
        if len(rest.split()) != 1:
            return Command("reject", error=f"usage: /{kind} <url>")
        return Command(kind, arg=rest)
    if kind == "sigil":
        if not rest:
            return Command("reject", error="usage: /sigil <words>")
        if len(rest) > _SIGIL_MAX:
            return Command("reject", error=f"sigil too long (max {_SIGIL_MAX})")
        return Command("sigil", arg=rest)
    # /crawl <url> [depth]
    args = rest.split()
    if not args or len(args) > 2:
        return Command("reject", error="usage: /crawl <url> [depth 1-4]")
    depth = None
    if len(args) == 2:
        try:
            depth = int(args[1])
        except ValueError:
            return Command("reject", error="usage: /crawl <url> [depth 1-4]")
        if not (MIN_DEPTH <= depth <= MAX_DEPTH):
            return Command("reject", error=f"usage: depth must be {MIN_DEPTH}-{MAX_DEPTH}")
    return Command("crawl", arg=args[0], depth=depth)
