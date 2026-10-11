"""Fail-closed access control: allowlisted users + optional groups, deny rest.

Nothing outside the allowlist is ever answered with bot content. A denied
private sender gets a single bounded "Access denied."; denied groups/channels
are answered with silence (no amplification, no existence signal).
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class AccessDecision:
    ok: bool
    reason: str
    chat_id: int | None = None
    user_id: int | None = None
    message_id: int | None = None
    chat_type: str | None = None
    thread_id: int | None = None     # message_thread_id (forum topic), preserved on reply


class Authorizer:
    def __init__(self, allowed_user_ids, allowed_group_ids=()):
        self.allowed_user_ids = set(allowed_user_ids)
        self.allowed_group_ids = set(allowed_group_ids or ())

    def decide(self, update: dict) -> AccessDecision:
        if not isinstance(update, dict):
            return AccessDecision(False, "malformed update")
        msg = update.get("message")
        if not isinstance(msg, dict):
            # edited_message / channel_post / callback_query etc. are ignored.
            return AccessDecision(False, "no message")
        frm = msg.get("from") or {}
        chat = msg.get("chat") or {}
        user_id = frm.get("id")
        chat_id = chat.get("id")
        chat_type = chat.get("type")
        message_id = msg.get("message_id")
        thread_id = msg.get("message_thread_id")

        base = dict(chat_id=chat_id, user_id=user_id,
                    message_id=message_id, chat_type=chat_type,
                    thread_id=thread_id)

        if user_id not in self.allowed_user_ids:
            return AccessDecision(False, "sender not allowlisted", **base)
        if chat_type == "private":
            return AccessDecision(True, "dm", **base)
        if chat_type in ("group", "supergroup"):
            if chat_id in self.allowed_group_ids:
                return AccessDecision(True, "group", **base)
            return AccessDecision(False, "group not allowlisted", **base)
        return AccessDecision(False, f"chat type not allowed: {chat_type}", **base)
