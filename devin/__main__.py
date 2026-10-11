"""Entry point. Refuses to start unless a valid env-only token + allowlist
are present. This is the ONLY path that performs real network I/O, and only
when explicitly run (`python -m devin`) — never imported by tests.

Run:  DEVIN_BOT_TOKEN=... DEVIN_ALLOWED_USERS=... [DEVIN_ALLOWED_GROUPS=...] \
      python -m devin
"""
from __future__ import annotations

from .config import ConfigError, load_config


def main() -> int:
    try:
        config = load_config()
    except ConfigError as e:
        raise SystemExit(f"config error: {e}") from e
    from . import transport
    from .bot import DevinBot
    bot = DevinBot(config, transport.telegram_call, transport.github_fetch)
    bot.run()
    return 0


if __name__ == "__main__":
    main()
