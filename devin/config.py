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
GITHUB_TOKEN_ENV = "DEVIN_GITHUB_TOKEN"
CREDENTIALS_DIR_ENV = "CREDENTIALS_DIRECTORY"
CREDENTIAL_FILENAME = "telegram_token"
GITHUB_CREDENTIAL_FILENAME = "github_token"
BUNDLE_CREDENTIAL_FILENAME = "bundle_passphrase"
BUNDLE_PASSPHRASE_ENV = "DEVIN_BUNDLE_PASSPHRASE"

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
    max_links: int = 50              # site-map internal links cap
    max_crawl_bytes: int = 2_000_000  # site-map seed page byte cap
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
    github_token: str | None = None     # optional; never printed (see __repr__)

    def __repr__(self) -> str:  # deliberately omits token AND github_token
        return (f"Config(allowed_user_ids={self.allowed_user_ids}, "
                f"allowed_group_ids={self.allowed_group_ids}, "
                f"bot_id={self.bot_id}, bot_username={self.bot_username!r}, "
                f"limits={self.limits!r})")


def _parse_ids(name: str, value: str | None) -> tuple[int, ...] | None:
    if value is None or value.strip() == "":
        return None
    ids: list[int] = []
    # Commas are the documented form, but systemd `Environment=` splits a value
    # on whitespace unless it is quoted — and an unquoted multi-value assignment
    # is silently truncated to its first token by systemd itself. Accept commas,
    # whitespace, and semicolons so either spelling of the unit works.
    for part in re.split(r"[,\s;]+", value.strip()):
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


def resolve_bundle_passphrase(env=None) -> str | None:
    """The passphrase used to seal /bundle artifacts.

    Credential directory first (systemd `LoadCredentialEncrypted`), then the
    environment. Returns None when unset — and None means /bundle REFUSES
    rather than sealing under a guessable default. The value is never logged,
    never returned in an error, and never part of Config's repr.
    """
    env = env if env is not None else os.environ
    cred_dir = env.get(CREDENTIALS_DIR_ENV)
    if cred_dir:
        path = os.path.join(cred_dir, BUNDLE_CREDENTIAL_FILENAME)
        try:
            with open(path, "r", encoding="utf-8") as fh:
                value = fh.read().strip()
            if value:
                return value
        except OSError:
            pass
    return (env.get(BUNDLE_PASSPHRASE_ENV) or "").strip() or None


def resolve_github_token(env=None) -> str | None:
    """Return the optional GitHub token from the systemd credential dir, else
    the env var. Empty when not configured (private repos simply won't work).

    Mirrors `resolve_token`: the credential file is preferred and is never
    exposed in ``systemctl show``/``ps`` output. The value is never logged.
    """
    env = env if env is not None else os.environ
    cred_dir = env.get(CREDENTIALS_DIR_ENV)
    if cred_dir:
        try:
            with open(os.path.join(cred_dir, GITHUB_CREDENTIAL_FILENAME)) as fh:
                tok = fh.read().strip()
            if tok:
                return tok
        except OSError:
            pass
    return (env.get(GITHUB_TOKEN_ENV) or "").strip()


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
    github_token = resolve_github_token(env) or None
    return Config(token=token, allowed_user_ids=users,
                  allowed_group_ids=groups, limits=Limits(),
                  bot_id=bot_id, bot_username=bot_username,
                  github_token=github_token)