"""Fail-closed access control: allowlisted users + optional groups, deny rest.

Nothing outside the allowlist is ever answered with bot content. A denied
private sender gets a single bounded "Access denied."; denied groups/channels
are answered with silence (no amplification, no existence signal).

a DM is authorized by the USER allowlist — or by ANY user when the allowlist
carries the open token (`*`), the owner's choice for a bot that serves the
public from his DMs. A group/supergroup is authorized by
the GROUP allowlist — the room is the principal, so any member may use the bot
once they address it (the bot layer still requires the address). An allowlisted
room that has not been allowlisted as a group is silence, not an error.
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
    def __init__(self, allowed_user_ids, allowed_group_ids=(), open_dms=False):
        self.allowed_user_ids = set(allowed_user_ids)
        self.allowed_group_ids = set(allowed_group_ids or ())
        # `open_dms` opens PRIVATE chats only. It is deliberately incapable of
        # opening a room: the group branch below never consults it, so a token
        # in the user allowlist cannot expose a group DEVin was not added to.
        self.open_dms = bool(open_dms)

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

        if chat_type == "private":
            if self.open_dms:
                return AccessDecision(True, "dm-open", **base)
            if user_id not in self.allowed_user_ids:
                return AccessDecision(False, "sender not allowlisted", **base)
            return AccessDecision(True, "dm", **base)
        if chat_type in ("group", "supergroup"):
            if chat_id not in self.allowed_group_ids:
                return AccessDecision(False, "group not allowlisted", **base)
            # An allowlisted room is the principal: every member may use the bot
            # (the bot layer still requires it to be addressed, so a room full of
            # people cannot make it talk over everyone). A bot sender reaches the
            # bot layer too, where only an addressed /command@self passes — that
            # is the sibling-loop breaker.
            if frm.get("is_bot"):
                return AccessDecision(True, "group-bot", **base)
            return AccessDecision(True, "group", **base)
        return AccessDecision(False, f"chat type not allowed: {chat_type}", **base)
