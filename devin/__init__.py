"""DEVin — offline Telegram bot scaffold (Looper #706 / ERC-8004 agent 87226).

Read-only, bounded, allowlisted. Source is inspected statically and never
executed. No x402 spend, no wallet access, no LLM prompt execution, no shell.

This package performs NO network I/O on import and holds NO credentials; the
bot token is read from the environment only, at startup.
"""
from __future__ import annotations

__version__ = "0.5.0"
