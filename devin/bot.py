"""DEVin Telegram bot — long-poll scaffold, offline, fail-closed.

The bot holds NO credentials itself; the token arrives only via `Config`
(loaded from the environment). All Telegram I/O and all GitHub fetches go
through injected callables, so the whole bot is unit-testable with mocked HTTP
and never touches the network in tests. The token is embedded only in the
request URL and is never logged, echoed, or sent as message text.
"""
from __future__ import annotations

import json
from dataclasses import dataclass

from .access import AccessDecision, Authorizer
from .commands import COMMANDS, Command, parse_command
from .config import Config
from .crawl_cmd import MapDenied, MapLimits, site_map
from .deep_audit import deep_repo_report
from .doctor import render_doctor
from .github_audit import AuditDenied, AuditLimits, audit_public_repo
from .report import (render_deep_report, render_help, render_report,
                     render_site_map, render_start)

TELEGRAM_API = "https://api.telegram.org"
POLL_ERROR_BACKOFF = 2.0
MAX_BACKOFF = 30.0


class TelegramError(Exception):
    """A Telegram API call failed; the description is safe (never token/URL)."""


@dataclass
class HandledResult:
    update_id: int | None
    action: str          # "replied" | "denied" | "error"
    detail: str = ""


class DevinBot:
    def __init__(self, config: Config, transport, github_fetch, public_fetch=None):
        self.config = config
        self.authorizer = Authorizer(config.allowed_user_ids,
                                     config.allowed_group_ids)
        self.transport = transport      # (url, method, body, timeout) -> Response
        self.github_fetch = github_fetch  # (url, timeout, headers=None) -> Response
        self.public_fetch = public_fetch  # (url, timeout) -> Response (site map)
        self._backoff = 0.0
        # Live identity, adopted from getMe at startup; seeded from config so
        # group addressing can be unit-tested without a network round trip.
        self.bot_id = config.bot_id
        self.bot_username = config.bot_username

    # ── Telegram plumbing (token embedded in URL only, never logged) ───────

    def _url(self, method: str) -> str:
        return f"{TELEGRAM_API}/bot{self.config.token}/{method}"

    def _call(self, method: str, params: dict | None) -> dict:
        url = self._url(method)
        body = json.dumps(params).encode() if params is not None else None
        resp = self.transport(url, "POST", body, self.config.limits.http_timeout)
        try:
            data = json.loads(resp.body.decode("utf-8"))
        except Exception:
            raise TelegramError(f"{method}: non-JSON response") from None
        if resp.status != 200 or not data.get("ok"):
            desc = (data.get("description") or "")[:200]
            raise TelegramError(f"{method} failed: {desc}")
        return data

    def _reply(self, chat_id, text, reply_to=None, thread_id=None):
        params = {"chat_id": chat_id,
                  "text": text[: self.config.limits.max_reply_len]}
        if reply_to is not None:
            params["reply_to_message_id"] = reply_to
        if thread_id is not None:
            params["message_thread_id"] = thread_id
        self._call("sendMessage", params)

    # ── startup identity guard (fail-closed) ────────────────────────────────

    def verify_startup(self) -> dict:
        """Confirm the token's identity and that long polling can receive.

        Called once before the poll loop. Raises `TelegramError` (fail-closed)
        if the token belongs to a different bot than the pinned identity, or if
        a webhook is set — in which case getUpdates would silently return
        nothing and the bot would appear alive while replying to no one.
        """
        me = self._call("getMe", None).get("result") or {}
        bot_id = me.get("id")
        username = me.get("username")
        if not isinstance(bot_id, int):
            raise TelegramError("getMe returned no bot identity")
        if self.config.bot_id is not None and bot_id != self.config.bot_id:
            raise TelegramError("bot identity does not match pinned DEVIN_BOT_ID")
        if (self.config.bot_username and username
                and username.lower() != self.config.bot_username.lower()):
            raise TelegramError("bot username does not match pinned DEVIN_BOT_USERNAME")
        wh = self._call("getWebhookInfo", None).get("result") or {}
        if wh.get("url"):
            raise TelegramError("a webhook is configured; long polling would miss updates")
        # Adopt the live identity for group @mention addressing.
        self.bot_id = bot_id
        self.bot_username = username
        return {"id": bot_id, "username": username}

    def _addressed_in_group(self, msg: dict, text: str | None) -> bool:
        """In a group the bot acts only when explicitly addressed: a command
        carrying its own ``@username`` mention, or a reply to one of its
        messages. Otherwise it stays silent (shared-group etiquette: several
        bots live in the same room and must not all answer one /command)."""
        if text:
            head = text.strip().split(None, 1)[0] if text.strip() else ""
            if head.startswith("/") and "@" in head:
                mention = head.split("@", 1)[1].strip().lower()
                if self.bot_username and mention == self.bot_username.lower():
                    return True
        reply = msg.get("reply_to_message") or {}
        frm = reply.get("from") or {}
        if frm.get("is_bot"):
            if self.bot_id is not None and frm.get("id") == self.bot_id:
                return True
            if (self.bot_username and frm.get("username")
                    and frm["username"].lower() == self.bot_username.lower()):
                return True
        return False

    # ── update handling ─────────────────────────────────────────────────────

    def _audit_limits(self) -> AuditLimits:
        L = self.config.limits
        return AuditLimits(max_files=L.max_repo_files,
                           max_file_bytes=L.max_file_bytes,
                           max_total_bytes=L.max_total_bytes,
                           max_findings=L.max_findings)

    def _map_limits(self) -> MapLimits:
        L = self.config.limits
        return MapLimits(max_links=L.max_links, max_bytes=L.max_crawl_bytes,
                         max_url_len=L.max_message_len)

    def handle_update(self, update: dict) -> HandledResult:
        uid = update.get("update_id") if isinstance(update, dict) else None
        decision = self.authorizer.decide(update)
        if not decision.ok:
            chat = (update.get("message") or {}).get("chat") or {}
            # Fail-closed: a bounded rejection only to a denied PRIVATE sender;
            # denied groups/channels get silence (no amplification).
            if chat.get("type") == "private" and decision.chat_id is not None:
                try:
                    self._reply(decision.chat_id, "Access denied.")
                except TelegramError:
                    pass
            return HandledResult(uid, "denied", decision.reason)

        msg = update.get("message") or {}
        text = msg.get("text")

        # Shared-group etiquette: in a group the bot speaks only when addressed
        # (explicit @mention or a reply to it). Non-addressed group messages are
        # ignored silently so several bots in one room never all answer.
        if decision.chat_type in ("group", "supergroup"):
            if not self._addressed_in_group(msg, text):
                return HandledResult(uid, "ignored", "not addressed in group")

        cmd = parse_command(text, self.config.limits.max_message_len)

        if cmd.kind == "start":
            self._reply(decision.chat_id, render_start(),
                        reply_to=decision.message_id, thread_id=decision.thread_id)
            return HandledResult(uid, "replied", "start")
        if cmd.kind == "help":
            self._reply(decision.chat_id, render_help(),
                        reply_to=decision.message_id, thread_id=decision.thread_id)
            return HandledResult(uid, "replied", "help")
        if cmd.kind == "audit":
            return self._handle_audit(uid, cmd, decision)
        if cmd.kind == "debug":
            return self._handle_debug(uid, cmd, decision)
        if cmd.kind == "map":
            return self._handle_map(uid, cmd, decision)
        if cmd.kind == "doctor":
            return self._handle_doctor(uid, cmd, decision)
        # reject
        reason = cmd.error or "unknown command"
        self._reply(decision.chat_id, f"{reason}. Allowed: {' '.join(COMMANDS)}",
                    reply_to=decision.message_id, thread_id=decision.thread_id)
        return HandledResult(uid, "replied", f"reject:{reason}")

    def _handle_audit(self, uid, cmd: Command, decision: AccessDecision) -> HandledResult:
        try:
            outcome = audit_public_repo(cmd.arg, self.github_fetch,
                                        limits=self._audit_limits(),
                                        timeout=self.config.limits.http_timeout,
                                        token=self.config.github_token)
            self._reply(decision.chat_id,
                        render_report(outcome, max_len=self.config.limits.max_reply_len),
                        reply_to=decision.message_id, thread_id=decision.thread_id)
            return HandledResult(uid, "replied", f"audit:{outcome.owner}/{outcome.repo}")
        except AuditDenied as e:
            self._reply(decision.chat_id, f"audit refused: {str(e)[:300]}",
                        reply_to=decision.message_id, thread_id=decision.thread_id)
            return HandledResult(uid, "replied", "audit-denied")
        except Exception:
            self._reply(decision.chat_id, "audit failed.",
                        reply_to=decision.message_id, thread_id=decision.thread_id)
            return HandledResult(uid, "replied", "audit-error")

    def _handle_debug(self, uid, cmd: Command, decision: AccessDecision) -> HandledResult:
        try:
            outcome = deep_repo_report(cmd.arg, self.github_fetch,
                                       limits=self._audit_limits(),
                                       timeout=self.config.limits.http_timeout,
                                       token=self.config.github_token)
            self._reply(decision.chat_id,
                        render_deep_report(outcome,
                                           max_len=self.config.limits.max_reply_len),
                        reply_to=decision.message_id, thread_id=decision.thread_id)
            return HandledResult(uid, "replied", f"debug:{outcome.owner}/{outcome.repo}")
        except AuditDenied as e:
            self._reply(decision.chat_id, f"debug refused: {str(e)[:300]}",
                        reply_to=decision.message_id, thread_id=decision.thread_id)
            return HandledResult(uid, "replied", "debug-denied")
        except Exception:
            self._reply(decision.chat_id, "debug failed.",
                        reply_to=decision.message_id, thread_id=decision.thread_id)
            return HandledResult(uid, "replied", "debug-error")

    def _handle_map(self, uid, cmd: Command, decision: AccessDecision) -> HandledResult:
        if self.public_fetch is None:
            self._reply(decision.chat_id, "map unavailable.",
                        reply_to=decision.message_id, thread_id=decision.thread_id)
            return HandledResult(uid, "replied", "map-unavailable")
        try:
            sm = site_map(cmd.arg, self.public_fetch, limits=self._map_limits(),
                          timeout=self.config.limits.http_timeout)
            self._reply(decision.chat_id,
                        render_site_map(sm, max_len=self.config.limits.max_reply_len),
                        reply_to=decision.message_id, thread_id=decision.thread_id)
            return HandledResult(uid, "replied", f"map:{sm.url}")
        except MapDenied as e:
            self._reply(decision.chat_id, f"map refused: {str(e)[:300]}",
                        reply_to=decision.message_id, thread_id=decision.thread_id)
            return HandledResult(uid, "replied", "map-denied")
        except Exception:
            self._reply(decision.chat_id, "map failed.",
                        reply_to=decision.message_id, thread_id=decision.thread_id)
            return HandledResult(uid, "replied", "map-error")

    def _handle_doctor(self, uid, cmd: Command, decision: AccessDecision) -> HandledResult:
        try:
            wh = self._call("getWebhookInfo", None).get("result") or {}
            text = render_doctor(
                self.config, bot_id=self.bot_id, bot_username=self.bot_username,
                webhook_url=(wh.get("url") or "") or None,
                max_len=self.config.limits.max_reply_len)
            self._reply(decision.chat_id, text,
                        reply_to=decision.message_id, thread_id=decision.thread_id)
            return HandledResult(uid, "replied", "doctor")
        except TelegramError:
            self._reply(decision.chat_id, "doctor failed.",
                        reply_to=decision.message_id, thread_id=decision.thread_id)
            return HandledResult(uid, "replied", "doctor-error")

    # ── polling ─────────────────────────────────────────────────────────────

    def poll_once(self, offset: int) -> tuple[int, list[HandledResult]]:
        """One non-blocking getUpdates round; returns (next_offset, results)."""
        data = self._call("getUpdates",
                          {"offset": offset, "timeout": 0,
                           "allowed_updates": ["message"]})
        results: list[HandledResult] = []
        updates = data.get("result") or []
        for u in updates:
            uid = u.get("update_id")
            if uid is None:
                continue
            offset = uid + 1
            results.append(self.handle_update(u))
        return offset, results

    def run(self, poll_timeout: int | None = None):
        """Long-poll loop. getUpdates timeouts are expected, not failures."""
        timeout = (poll_timeout if poll_timeout is not None
                   else self.config.limits.poll_timeout)
        self.verify_startup()   # fail-closed on wrong identity / set webhook
        offset = 0
        while True:
            try:
                data = self._call("getUpdates",
                                  {"offset": offset, "timeout": timeout,
                                   "allowed_updates": ["message"]})
                self._backoff = 0.0
                for u in (data.get("result") or []):
                    uid = u.get("update_id")
                    if uid is None:
                        continue
                    offset = uid + 1
                    self.handle_update(u)
            except TelegramError as e:
                if self._is_auth_error(e):
                    raise            # fail-closed: invalid/revoked token -> stop
                self._backoff = min(MAX_BACKOFF,
                                    (self._backoff or POLL_ERROR_BACKOFF) * 1.5)
            except Exception:
                self._backoff = min(MAX_BACKOFF,
                                    (self._backoff or POLL_ERROR_BACKOFF) * 1.5)

    @staticmethod
    def _is_auth_error(e: TelegramError) -> bool:
        s = str(e)
        return "Unauthorized" in s or "401" in s or "Forbidden" in s
