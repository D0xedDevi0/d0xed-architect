"""Bounded self-diagnostics for DEVin.

Reports only safe, bounded facts: package version, bot identity, allowlist
COUNTS (never the IDs), webhook status, whether a GitHub token is configured
(boolean only — the value is never rendered), and the configured limits.
"""
from __future__ import annotations

from . import __version__
from .config import Config


def render_doctor(config: Config, *, bot_id: int | None = None,
                  bot_username: str | None = None,
                  webhook_url: str | None = None,
                  max_len: int = 500) -> str:
    """Render a bounded diagnostics block. Never prints either token value."""
    L = config.limits
    webhook = "set" if webhook_url else "clear"
    gh = "yes" if config.github_token else "no"
    lines = [
        f"DEVin {__version__} — self-diagnostics",
        f"bot: id={bot_id if bot_id is not None else 'unknown'} "
        f"username={bot_username or 'unknown'}",
        f"allowlist: users={len(config.allowed_user_ids)} "
        f"groups={len(config.allowed_group_ids)}",
        f"webhook: {webhook}",
        f"github token configured: {gh}",
        (f"limits: msg={L.max_message_len} reply={L.max_reply_len} "
         f"files={L.max_repo_files} fileB={L.max_file_bytes} "
         f"totalB={L.max_total_bytes} findings={L.max_findings} "
         f"links={L.max_links} timeout={L.http_timeout}"),
    ]
    text = "\n".join(lines)
    if len(text) > max_len:
        text = text[: max_len - 20] + "\n…(truncated)"
    return text
