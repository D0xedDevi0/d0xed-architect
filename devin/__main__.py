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
    from .config import resolve_bundle_passphrase
    # None when unprovisioned, which makes /bundle refuse instead of sealing
    # under a default. Never printed, never logged.
    bot = DevinBot(config, transport.telegram_call, transport.github_fetch,
                   transport.public_fetch,
                   bundle_passphrase=resolve_bundle_passphrase(),
                   file_get=transport.telegram_file_get,
                   # The social layer's OPTIONAL model, bound from an env-gated,
                   # host-allowlisted endpoint. None (the default) means the
                   # authored voice in `voice.py` answers everything — no
                   # network, no key. The value is never printed or logged; the
                   # startup line says only "voice=model|authored-only".
                   llm=transport.make_llm(config.llm),
                   # One journal line per update (no message text, no secrets),
                   # so a silent bot is diagnosable instead of a mystery.
                   verbose=True)
    bot.run()
    return 0


if __name__ == "__main__":
    main()
