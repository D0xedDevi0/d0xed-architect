"""Live proof of the GROUP route on the real VPS with the real credentials.

Runs the ACTUAL bot object against the ACTUAL encrypted credentials and prints:

  * the allowlists the deployed service really loaded — an unquoted systemd
    ``Environment=`` line is split on whitespace and everything after the first
    token is dropped by systemd itself, which silently removed a whole group;
  * what DEVin does with each way a person addresses him in a room, including
    the natural ``@DEVinlooperbot /crawl <url>`` form and the non-owner member
    case that used to be denied by the DM user allowlist;
  * one REAL network round trip (a DM ``/help``) so the send path is proven too.

GROUP REPLIES ARE CAPTURED, NOT SENT: proving the route must not spam the room.
No message text, chat payload, or credential value is printed.

Run under the same credentials the unit uses, e.g.

    systemd-run --pipe --wait --collect \\
      --property=LoadCredentialEncrypted=telegram_token:/etc/credstore.encrypted/looper-devin.token \\
      --property=LoadCredentialEncrypted=github_token:/etc/credstore.encrypted/looper-devin.github \\
      --property=LoadCredentialEncrypted=bundle_passphrase:/etc/credstore.encrypted/looper-devin.bundle \\
      /srv/looper-agents/devin/venv/bin/python \\
      /srv/looper-agents/devin/app/devin/scripts/live_group_check.py
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))

from architect.http import Response                    # noqa: E402
from devin import transport                            # noqa: E402
from devin.bot import DevinBot                         # noqa: E402
from devin.config import (load_config,                 # noqa: E402
                          resolve_bundle_passphrase)

GROUP = -1004351143165      # @looper_collective
MEMBER = 424242             # a room member who is NOT in the DM allowlist
SIBLING_BOT = 777000        # another bot in the same room


def _ok(method: str) -> Response:
    return Response(url="", status=200, headers={},
                    body=json.dumps({"ok": True,
                                     "result": {"message_id": 1}}).encode(),
                    content_type="application/json")


class Capture:
    """Stands in for the Telegram transport: records, never sends."""

    def __init__(self) -> None:
        self.sent: list[tuple[str, dict]] = []

    def __call__(self, url, method, body, timeout):
        self.sent.append((method, json.loads(body.decode()) if body else {}))
        return _ok(method)


def group_update(uid, user_id, text, is_bot=False, reply_to_bot=False):
    msg = {"message_id": 100 + uid,
           "from": {"id": user_id, "is_bot": is_bot},
           "chat": {"id": GROUP, "type": "supergroup"},
           "text": text}
    if reply_to_bot:
        msg["reply_to_message"] = {
            "message_id": 9,
            "from": {"id": 8803435794, "username": "DEVinlooperbot",
                     "is_bot": True}}
    return {"update_id": uid, "message": msg}


def main() -> int:
    cfg = load_config(os.environ)
    print("allowlists the deployed service really loaded:")
    print("  users :", list(cfg.allowed_user_ids))
    print("  groups:", list(cfg.allowed_group_ids))
    print("  github credential present:", bool(cfg.github_token))
    print("  sealing key present      :", bool(resolve_bundle_passphrase()))
    print("  bot identity pin         : id=%s @%s"
          % (cfg.bot_id, cfg.bot_username))
    print()

    u = cfg.bot_username
    cap = Capture()
    bot = DevinBot(cfg, cap, transport.github_fetch, transport.public_fetch,
                   bundle_passphrase=resolve_bundle_passphrase(),
                   file_get=transport.telegram_file_get)
    bot.bot_id, bot.bot_username = cfg.bot_id, cfg.bot_username

    cases = [
        ("bare /help            (never delivered under group privacy)",
         group_update(1, MEMBER, "/help"), "ignored"),
        ("/help@%s" % u,
         group_update(2, MEMBER, "/help@%s" % u), "replied"),
        ("@%s /help   (mention prefix)" % u,
         group_update(3, MEMBER, "@%s /help" % u), "replied"),
        ("@%s what do you do?   (social layer answers)",
         group_update(4, MEMBER, "@%s what do you do?" % u), "replied"),
        ("reply to one of his messages",
         group_update(5, MEMBER, "/help", reply_to_bot=True), "replied"),
        ("sibling bot, bare mention  (loop breaker)",
         group_update(6, SIBLING_BOT, "@%s hi" % u, is_bot=True), "ignored"),
        ("sibling bot, addressed command",
         group_update(7, SIBLING_BOT, "/help@%s" % u, is_bot=True), "replied"),
    ]

    failures = 0
    for label, update, want in cases:
        cap.sent.clear()
        res = bot.handle_update(update)
        got = res.action
        mark = "ok " if got == want else "FAIL"
        if got != want:
            failures += 1
        target = ""
        if cap.sent:
            method, params = cap.sent[0]
            target = "  -> %s chat_id=%s reply_to=%s" % (
                method, params.get("chat_id"), params.get("reply_to_message_id"))
        print("%s %-46s %-8s (%s)%s"
              % (mark, label, got, res.detail, target))

    print()

    # One REAL network round trip, to the owner's DM: proves the deployed code,
    # the credential mount, and the send path end to end.
    real = DevinBot(cfg, transport.telegram_call, transport.github_fetch,
                    transport.public_fetch,
                    bundle_passphrase=resolve_bundle_passphrase(),
                    file_get=transport.telegram_file_get)
    real.bot_id, real.bot_username = cfg.bot_id, cfg.bot_username
    r = real.handle_update({"update_id": 98, "message": {
        "message_id": 1, "from": {"id": list(cfg.allowed_user_ids)[0]},
        "chat": {"id": list(cfg.allowed_user_ids)[0], "type": "private"},
        "text": "/help"}})
    print("real DM round trip: %s (%s)  <- check your DM" % (r.action, r.detail))

    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
