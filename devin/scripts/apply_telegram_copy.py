"""Apply the Telegram profile copy + command menu from `devin.report`.

Single source of truth: the Description, About/short description and command
menu are read from the constants in `devin/report.py`, so the live profile can
never drift from the code the bot actually runs. Never hand-set any of it.

The bot token is read from the systemd credential directory
(`$CREDENTIALS_DIRECTORY/telegram_token`) or `$DEVIN_BOT_TOKEN`. It is never
printed, never echoed, and never included in an error message.

Run on the VPS (the credential is decrypted only for the unit that asks for it):

    systemd-run --collect --wait --property=User=looper-devin \\
      --property=LoadCredentialEncrypted=telegram_token:/etc/credstore.encrypted/looper-devin.token \\
      /srv/looper-agents/devin/venv/bin/python -m devin.scripts.apply_telegram_copy

Add `--dry-run` to print what WOULD be sent without calling the API.
"""
from __future__ import annotations

import json
import os
import sys
import urllib.request

from ..report import ABOUT, COMMANDS, DESCRIPTION

API = "https://api.telegram.org"
TIMEOUT = 20


class CopyError(Exception):
    """The copy could not be applied."""


def resolve_token(env: dict | None = None) -> str:
    """Credential dir first (systemd), then the environment. Never logged."""
    env = env if env is not None else os.environ
    cred_dir = env.get("CREDENTIALS_DIRECTORY")
    if cred_dir:
        path = os.path.join(cred_dir, "telegram_token")
        try:
            with open(path, "r", encoding="utf-8") as fh:
                tok = fh.read().strip()
            if tok:
                return tok
        except OSError:
            pass
    tok = (env.get("DEVIN_BOT_TOKEN") or "").strip()
    if not tok:
        raise CopyError("no telegram token in the credential directory or "
                        "DEVIN_BOT_TOKEN")
    return tok


def _call(token: str, method: str, payload: dict) -> dict:
    url = f"{API}/bot{token}/{method}"
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url, data=body, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return json.loads(r.read().decode("utf-8", "replace"))
    except Exception as e:
        # Never surface the URL — it contains the token.
        raise CopyError(f"{method} failed: {type(e).__name__}") from None


def apply_copy(token: str, dry_run: bool = False, call=None) -> list:
    """Apply description, short description and the command menu.

    Returns a list of (method, ok, detail). `detail` is a length for successes
    and Telegram's own description for failures — Telegram's description never
    echoes the token.
    """
    call = call or _call
    jobs = [
        ("setMyDescription", {"description": DESCRIPTION}, len(DESCRIPTION)),
        ("setMyShortDescription", {"short_description": ABOUT}, len(ABOUT)),
        ("setMyCommands", {"commands": COMMANDS}, len(COMMANDS)),
    ]
    results: list = []
    for method, payload, size in jobs:
        if dry_run:
            results.append((method, True, f"dry-run ({size})"))
            continue
        resp = call(token, method, payload)
        ok = bool(resp.get("ok"))
        detail = str(size) if ok else str(resp.get("description", "rejected"))[:160]
        results.append((method, ok, detail))
    return results


def main(argv: list | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    dry_run = "--dry-run" in argv
    try:
        token = "dry-run" if dry_run else resolve_token()
        for method, ok, detail in apply_copy(token, dry_run=dry_run):
            print(f"{'OK ' if ok else 'ERR'} {method}: {detail}")
        return 0
    except CopyError as e:
        print(f"ERR {e}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
