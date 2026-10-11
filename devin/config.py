"""Fail-closed configuration, sourced from the environment or a systemd
credential directory ONLY.

The bot token is never hardcoded, logged, or echoed. A missing or malformed
token (or allowlist) raises `ConfigError` and prevents startup — fail-closed,
not fail-open. Allowlists are comma-separated ID lists; when a required list is
unset or empty, startup is refused.

Token resolution order (first non-empty wins):
  1. ``$CREDENTIALS_DIRECTORY/telegram_token`` — a systemd `LoadCredentialEncrypted`
     file, readable only by the service user. This is the production source.
  2. ``DEVIN_BOT_TOKEN`` — a plain environment variable, used only for local
     development and tests.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass

TOKEN_ENV = "DEVIN_BOT_TOKEN"
USERS_ENV = "DEVIN_ALLOWED_USERS"
GROUPS_ENV = "DEVIN_ALLOWED_GROUPS"
BOT_ID_ENV = "DEVIN_BOT_ID"
BOT_USERNAME_ENV = "DEVIN_BOT_USERNAME"
CREDENTIALS_DIR_ENV = "CREDENTIALS_DIRECTORY"
CREDENTIAL_FILENAME = "telegram_token"

# Telegram bot tokens are "<bot_id>:<secret>". Validate shape only — the value
# is never stored in a repr, log, or error message.
_TOKEN_RE = re.compile(r"^\d{6,12}:[A-Za-z0-9_-]{30,}$")


class ConfigError(ValueError):
    """Raised when required configuration is missing or invalid."""


@dataclass(frozen=True)
class Limits:
    """Hard bounds. Every one of them is a safety limit, not a preference."""

    max_message_len: int = 500
    max_repo_files: int = 200
    max_file_bytes: int = 200_000
    max_total_bytes: int = 4_000_000
    max_findings: int = 50
    max_reply_len: int = 3600
    http_timeout: float = 60.0   # > poll_timeout, so a long-poll read never 404s
    poll_timeout: int = 30       # getUpdates long-poll wait (seconds)


@dataclass(frozen=True)
class Config:
    token: str                     # never printed
    allowed_user_ids: tuple[int, ...]
    allowed_group_ids: tuple[int, ...]
    limits: Limits
    bot_id: int | None = None           # expected bot identity (pinned at startup)
    bot_username: str | None = None     # used for group @mention addressing

    def __repr__(self) -> str:  # deliberately omits the token
        return (f"Config(allowed_user_ids={self.allowed_user_ids}, "
                f"allowed_group_ids={self.allowed_group_ids}, "
                f"bot_id={self.bot_id}, bot_username={self.bot_username!r}, "
                f"limits={self.limits!r})")


def _parse_ids(name: str, value: str | None) -> tuple[int, ...] | None:
    if value is None or value.strip() == "":
        return None
    ids: list[int] = []
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            ids.append(int(part))
        except ValueError:
            raise ConfigError(f"{name} must be comma-separated integers") from None
    return tuple(ids) if ids else None


def resolve_token(env=None) -> str:
    """Return the bot token from the systemd credential dir, else the env var.

    The credential file is preferred: it is the production source and is not
    exposed in ``systemctl show``/``ps`` output the way an Environment= var is.
    """
    env = env if env is not None else os.environ
    cred_dir = env.get(CREDENTIALS_DIR_ENV)
    if cred_dir:
        try:
            with open(os.path.join(cred_dir, CREDENTIAL_FILENAME)) as fh:
                tok = fh.read().strip()
            if tok:
                return tok
        except OSError:
            pass
    return (env.get(TOKEN_ENV) or "").strip()


def load_config(env=None) -> Config:
    """Load and validate configuration from `env` (defaults to os.environ)."""
    env = env if env is not None else os.environ
    token = resolve_token(env)
    if not token:
        raise ConfigError(f"missing {TOKEN_ENV}")
    if not _TOKEN_RE.match(token):
        raise ConfigError("invalid bot token format")
    users = _parse_ids(USERS_ENV, env.get(USERS_ENV))
    if not users:
        raise ConfigError(f"missing {USERS_ENV}")
    groups = _parse_ids(GROUPS_ENV, env.get(GROUPS_ENV)) or ()
    bot_id = None
    raw_id = (env.get(BOT_ID_ENV) or "").strip()
    if raw_id:
        try:
            bot_id = int(raw_id)
        except ValueError:
            raise ConfigError(f"{BOT_ID_ENV} must be an integer") from None
    bot_username = (env.get(BOT_USERNAME_ENV) or "").strip() or None
    return Config(token=token, allowed_user_ids=users,
                  allowed_group_ids=groups, limits=Limits(),
                  bot_id=bot_id, bot_username=bot_username)