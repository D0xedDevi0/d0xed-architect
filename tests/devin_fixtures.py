"""Shared fixtures for DEVin tests. No real network, no real credentials.

FAKE_TOKEN is a structurally-valid but worthless placeholder — it is NOT a
credential and is used only to prove the bot never echoes a token into chat.
"""
from __future__ import annotations

import io
import json
import tarfile

from architect.http import Response

FAKE_TOKEN = "123456789:" + "A" * 35
FAKE_GITHUB_TOKEN = "ghp_" + "A" * 36   # structurally valid, worthless placeholder
USER_ID = 7898354400
GROUP_ID = -1004351143165
BOT_ID = 8803435794
BOT_USERNAME = "DEVinlooperbot"


def make_response(status=200, body=b"", content_type="application/json") -> Response:
    return Response(url="", status=status, headers={}, body=body,
                    content_type=content_type)


def build_tarball(entries: dict) -> bytes:
    """Build an in-memory gzipped tarball. Values are bytes, or
    ("symlink", target) to add a symbolic link."""
    buf = io.BytesIO()
    prefix = "repo-main"
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for rel, payload in entries.items():
            name = f"{prefix}/{rel}"
            if isinstance(payload, tuple) and payload and payload[0] == "symlink":
                ti = tarfile.TarInfo(name)
                ti.type = tarfile.SYMTYPE
                ti.linkname = payload[1]
                tf.addfile(ti)
                continue
            data = payload if isinstance(payload, bytes) else b""
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            ti.mode = 0o644
            tf.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


class FakeGithub:
    """Injected GitHub transport: (url, timeout, headers=None) -> Response."""

    def __init__(self, tarball=b"", branch="main", meta_status=200,
                 tar_status=200, meta_extra=None, private=False):
        self.tarball = tarball
        self.branch = branch
        self.meta_status = meta_status
        self.tar_status = tar_status
        self.meta_extra = meta_extra or {}
        self.private = private
        self.calls: list[str] = []
        self.headers_seen: list[tuple[str, dict | None]] = []

    @staticmethod
    def _auth(headers):
        if not headers:
            return None
        for k, v in headers.items():
            if k.lower() == "authorization":
                return v
        return None

    def __call__(self, url, timeout, headers=None):
        self.calls.append(url)
        self.headers_seen.append((url, headers))
        auth = self._auth(headers)
        if "api.github.com" in url:
            if self.private and not auth:
                return make_response(404, b'{"message":"Not Found"}')
            if self.meta_status != 200:
                return make_response(self.meta_status, b'{"message":"nope"}')
            info = {"default_branch": self.branch}
            info.update(self.meta_extra)
            return make_response(200, json.dumps(info).encode())
        if "codeload.github.com" in url:
            if self.private and not auth:
                return make_response(404, b"nope")
            if self.tar_status != 200:
                return make_response(self.tar_status, b"nope")
            return make_response(200, self.tarball, content_type="application/gzip")
        return make_response(404, b"{}")


class FakePublic:
    """Injected public-web transport for /map: url -> (status, body, ctype)."""

    def __init__(self, pages=None):
        self.pages = pages or {}
        self.calls: list[str] = []

    def __call__(self, url, timeout, headers=None):
        self.calls.append(url)
        entry = self.pages.get(url)
        if entry is None:
            return make_response(404, b"")
        status, body, ctype = entry
        return make_response(status, body, ctype)


def html_page(title, links):
    """Build a minimal HTML page with <a href>s. links is a list of hrefs."""
    body = f"<html><head><title>{title}</title></head><body>"
    for href in links:
        body += f'<a href="{href}">link</a>'
    body += "</body></html>"
    return body.encode()


class FakeTelegram:
    """Injected Telegram transport: (url, method, body, timeout) -> Response."""

    def __init__(self, updates=None, bot_id=BOT_ID, bot_username=BOT_USERNAME,
                 webhook_url="", photo_ok=True):
        self.updates = updates or []
        self.bot_id = bot_id
        self.bot_username = bot_username
        self.webhook_url = webhook_url
        self.photo_ok = photo_ok
        self.sent: list[dict] = []    # sendMessage params captured
        self.photos: list[dict] = []  # sendPhoto params captured
        self.urls: list[str] = []

    def __call__(self, url, method, body, timeout):
        self.urls.append(url)
        params = json.loads(body.decode()) if body else {}
        name = url.rsplit("/", 1)[-1]
        if name == "getUpdates":
            return make_response(200, json.dumps(
                {"ok": True, "result": self.updates}).encode())
        if name == "sendMessage":
            self.sent.append(params)
            return make_response(200, json.dumps(
                {"ok": True, "result": {"message_id": 1}}).encode())
        if name == "sendPhoto":
            self.photos.append(params)
            if not self.photo_ok:
                return make_response(400, json.dumps(
                    {"ok": False, "description": "wrong file identifier"}).encode())
            return make_response(200, json.dumps(
                {"ok": True, "result": {"message_id": 1}}).encode())
        if name == "getMe":
            return make_response(200, json.dumps({"ok": True, "result": {
                "id": self.bot_id, "username": self.bot_username,
                "is_bot": True}}).encode())
        if name == "getWebhookInfo":
            return make_response(200, json.dumps({"ok": True, "result": {
                "url": self.webhook_url}}).encode())
        return make_response(200, json.dumps({"ok": True, "result": True}).encode())


def dm_update(update_id, user_id, text, message_id=1, thread_id=None):
    msg = {"message_id": message_id,
           "from": {"id": user_id},
           "chat": {"id": user_id, "type": "private"},
           "text": text}
    if thread_id is not None:
        msg["message_thread_id"] = thread_id
    return {"update_id": update_id, "message": msg}


def group_update(update_id, user_id, chat_id, text, message_id=1,
                 thread_id=None, reply_to_bot=False, reply_from_id=None):
    msg = {"message_id": message_id,
           "from": {"id": user_id},
           "chat": {"id": chat_id, "type": "supergroup"},
           "text": text}
    if thread_id is not None:
        msg["message_thread_id"] = thread_id
    if reply_to_bot:
        rid = reply_from_id if reply_from_id is not None else BOT_ID
        is_bot = rid == BOT_ID
        msg["reply_to_message"] = {
            "message_id": message_id - 1,
            "from": {"id": rid,
                     "username": BOT_USERNAME if is_bot else "someone",
                     "is_bot": is_bot}}
    return {"update_id": update_id, "message": msg}