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
from .analysis import AnalysisLimits
from .deep_audit import deep_repo_report, deep_tree_report
from .doctor import render_doctor
from .github_audit import AuditDenied, AuditLimits, audit_public_repo
from .crawl2 import (CrawlDenied, CrawlLimits, crawl_site, render_crawl,
                     render_sitemap, sitemap_inventory)
from .pack import (PackError, PackLimits, PackRefused, build_pack, pack_github,
                   render_pack)
from .upload import (MAX_UPLOAD_BYTES, UploadDenied, cleanup, download_cap,
                     intake, parse_document, safe_file_path, sniff)
from .report import (PHOTO, render_deep_report, render_help, render_link,
                     render_lore, render_report, render_site_map, render_start)

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
    def __init__(self, config: Config, transport, github_fetch, public_fetch=None,
                 bundle_passphrase: str | None = None, file_get=None,
                 transport_max_bytes: int = MAX_UPLOAD_BYTES):
        self.config = config
        self.authorizer = Authorizer(config.allowed_user_ids,
                                     config.allowed_group_ids)
        self.transport = transport      # (url, method, body, timeout) -> Response
        self.github_fetch = github_fetch  # (url, timeout, headers=None) -> Response
        self.public_fetch = public_fetch  # (url, timeout) -> Response (site map)
        # Held only in memory, never logged, never in a repr. None disables
        # /bundle outright (fail-closed: no key, no sealed artifact).
        self.bundle_passphrase = bundle_passphrase
        # Document intake: `file_get(url, timeout) -> Response`, host-pinned to
        # api.telegram.org. None disables upload intake entirely (fail-closed).
        self.file_get = file_get
        self.transport_max_bytes = int(transport_max_bytes)
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

    def _send_welcome(self, decision: AccessDecision, payload: str | None = None):
        """Open with Looper #706's art + the welcome caption. Telegram fetches
        the image URL itself (the bot makes no outbound request for it). Falls
        back to a plain sendMessage if the photo is rejected, so /start always
        lands something.

        `payload` is the deep-link tail of `?start=<payload>`. It is sanitized
        in the parser and only ever selects the opening line of the caption.
        """
        caption = render_start(payload)[:1024]        # telegram caption cap
        params = {"chat_id": decision.chat_id, "photo": PHOTO,
                  "caption": caption}
        if decision.message_id is not None:
            params["reply_to_message_id"] = decision.message_id
        if decision.thread_id is not None:
            params["message_thread_id"] = decision.thread_id
        try:
            self._call("sendPhoto", params)
        except TelegramError:
            self._reply(decision.chat_id, caption,
                        reply_to=decision.message_id, thread_id=decision.thread_id)

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

    def _crawl_limits(self, depth: int | None) -> CrawlLimits:
        """A crawl spends someone else's bandwidth, so the page budget is
        derived from the configured link budget rather than being unbounded."""
        L = self.config.limits
        pages = max(4, min(24, L.max_links // 4))
        return CrawlLimits(max_pages=pages, max_depth=depth or 2,
                           max_page_bytes=L.max_file_bytes,
                           max_total_bytes=max(L.max_crawl_bytes * 4, 4_000_000),
                           max_url_len=L.max_message_len,
                           fetch_timeout=min(L.http_timeout, 20.0))

    def handle_update(self, update: dict) -> HandledResult:
        uid = update.get("update_id") if isinstance(update, dict) else None
        decision = self.authorizer.decide(update)
        if not decision.ok:
            chat = (update.get("message") or {}).get("chat") or {}
            # Fail-closed: a bounded rejection only to a denied PRIVATE sender;
            # denied groups/channels get silence (no amplification).
            if chat.get("type") == "private" and decision.chat_id is not None:
                try:
                    self._reply(decision.chat_id, "Not on the list.")
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

        # An uploaded archive IS the command: there is no text to parse. Group
        # uploads are ignored above (not addressed) and refused below (DM only).
        if not text and isinstance(msg.get("document"), dict):
            return self._handle_document(uid, msg, decision)

        cmd = parse_command(text, self.config.limits.max_message_len)

        if cmd.kind == "start":
            self._send_welcome(decision, cmd.arg)
            return HandledResult(uid, "replied", f"start:{cmd.arg or '-'}")
        if cmd.kind == "help":
            self._reply(decision.chat_id, render_help(),
                        reply_to=decision.message_id, thread_id=decision.thread_id)
            return HandledResult(uid, "replied", "help")
        if cmd.kind == "lore":
            self._reply(decision.chat_id,
                        render_lore(max_len=self.config.limits.max_reply_len),
                        reply_to=decision.message_id, thread_id=decision.thread_id)
            return HandledResult(uid, "replied", "lore")
        if cmd.kind == "audit":
            return self._handle_audit(uid, cmd, decision)
        if cmd.kind == "debug":
            return self._handle_debug(uid, cmd, decision)
        if cmd.kind == "map":
            return self._handle_map(uid, cmd, decision)
        if cmd.kind == "crawl":
            return self._handle_crawl(uid, cmd, decision)
        if cmd.kind == "sitemap":
            return self._handle_sitemap(uid, cmd, decision)
        if cmd.kind == "link":
            return self._handle_link(uid, cmd, decision)
        if cmd.kind == "bundle":
            return self._handle_bundle(uid, cmd, decision)
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
            self._reply(decision.chat_id, f"audit refused — {str(e)[:300]}",
                        reply_to=decision.message_id, thread_id=decision.thread_id)
            return HandledResult(uid, "replied", "audit-denied")
        except Exception:
            self._reply(decision.chat_id, "No read — try again.",
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
            self._reply(decision.chat_id, f"debug refused — {str(e)[:300]}",
                        reply_to=decision.message_id, thread_id=decision.thread_id)
            return HandledResult(uid, "replied", "debug-denied")
        except Exception:
            self._reply(decision.chat_id, "No read — try again.",
                        reply_to=decision.message_id, thread_id=decision.thread_id)
            return HandledResult(uid, "replied", "debug-error")

    def _handle_map(self, uid, cmd: Command, decision: AccessDecision) -> HandledResult:
        if self.public_fetch is None:
            self._reply(decision.chat_id, "No map here.",
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
            self._reply(decision.chat_id, f"map refused — {str(e)[:300]}",
                        reply_to=decision.message_id, thread_id=decision.thread_id)
            return HandledResult(uid, "replied", "map-denied")
        except Exception:
            self._reply(decision.chat_id, "No map — try again.",
                        reply_to=decision.message_id, thread_id=decision.thread_id)
            return HandledResult(uid, "replied", "map-error")

    def _handle_crawl(self, uid, cmd: Command, decision: AccessDecision) -> HandledResult:
        try:
            rep = crawl_site(cmd.arg, self.public_fetch,
                             limits=self._crawl_limits(cmd.depth))
            self._reply(decision.chat_id,
                        render_crawl(rep, max_len=self.config.limits.max_reply_len),
                        reply_to=decision.message_id, thread_id=decision.thread_id)
            return HandledResult(uid, "replied", f"crawl:{rep.origin}")
        except CrawlDenied as e:
            self._reply(decision.chat_id, f"crawl refused — {str(e)[:300]}",
                        reply_to=decision.message_id, thread_id=decision.thread_id)
            return HandledResult(uid, "replied", "crawl-denied")
        except Exception:
            self._reply(decision.chat_id, "No crawl — try again.",
                        reply_to=decision.message_id, thread_id=decision.thread_id)
            return HandledResult(uid, "replied", "crawl-error")

    def _handle_sitemap(self, uid, cmd: Command, decision: AccessDecision) -> HandledResult:
        try:
            origin, sitemaps, urls, nested = sitemap_inventory(
                cmd.arg, self.public_fetch, limits=self._crawl_limits(None))
            self._reply(decision.chat_id,
                        render_sitemap(origin, sitemaps, urls, nested,
                                       max_len=self.config.limits.max_reply_len),
                        reply_to=decision.message_id, thread_id=decision.thread_id)
            return HandledResult(uid, "replied", f"sitemap:{origin}")
        except CrawlDenied as e:
            self._reply(decision.chat_id, f"sitemap refused — {str(e)[:300]}",
                        reply_to=decision.message_id, thread_id=decision.thread_id)
            return HandledResult(uid, "replied", "sitemap-denied")
        except Exception:
            self._reply(decision.chat_id, "No sitemap — try again.",
                        reply_to=decision.message_id, thread_id=decision.thread_id)
            return HandledResult(uid, "replied", "sitemap-error")

    def _handle_link(self, uid, cmd: Command, decision: AccessDecision) -> HandledResult:
        """Shareable links, built from the LIVE getMe username so the copy can
        never drift from the identity the token actually belongs to."""
        username = self.bot_username or self.config.bot_username
        self._reply(decision.chat_id, render_link(username),
                    reply_to=decision.message_id, thread_id=decision.thread_id)
        return HandledResult(uid, "replied", "link")

    def _pack_limits(self) -> PackLimits:
        L = self.config.limits
        return PackLimits(max_files=max(50, L.max_repo_files * 4),
                          max_file_bytes=L.max_file_bytes,
                          max_total_bytes=L.max_total_bytes,
                          max_bundle_bytes=20_000_000)

    def _send_document(self, chat_id, filename, blob, caption=None, *,
                       thread_id=None, boundary="----devinbundle"):
        """Send one file as multipart/form-data (sendDocument).

        The transport must opt into multipart: a plain 4-argument transport
        raises TypeError and we fail CLOSED and loudly, rather than pretending
        the artifact shipped.
        """
        safe_name = "".join(c for c in (filename or "bundle.enc")
                            if c.isalnum() or c in "._-")[:64] or "bundle.enc"
        body_parts = []

        def field(name, value):
            body_parts.append(
                (f"--{boundary}\r\nContent-Disposition: form-data; "
                 f'name="{name}"\r\n\r\n{value}\r\n').encode("utf-8"))

        field("chat_id", str(chat_id))
        if caption:
            field("caption", caption[:1024])      # telegram caption cap
        if thread_id is not None:
            field("message_thread_id", str(thread_id))
        body_parts.append(
            (f"--{boundary}\r\nContent-Disposition: form-data; "
             f'name="document"; filename="{safe_name}"\r\n'
             "Content-Type: application/octet-stream\r\n\r\n").encode("utf-8"))
        body_parts.append(blob)
        body_parts.append(f"\r\n--{boundary}--\r\n".encode("utf-8"))
        body = b"".join(body_parts)
        ctype = f"multipart/form-data; boundary={boundary}"
        try:
            resp = self.transport(self._url("sendDocument"), "POST", body,
                                  self.config.limits.http_timeout, ctype)
        except TypeError:
            raise TelegramError("document transport cannot carry multipart")
        if resp.status != 200:
            raise TelegramError(f"sendDocument failed: {resp.status}")
        return resp

    def _handle_bundle(self, uid, cmd: Command, decision: AccessDecision) -> HandledResult:
        """Seal a public repo into ONE encrypted file — DM only.

        Three deliberate refusals live here: no groups (the sealed file is
        somebody's source code), no passphrase means no bundle (rather than
        sealing under a guessable default), and live credentials block the
        seal unless explicitly acknowledged.
        """
        if (decision.chat_type or "").lower() != "private":
            self._reply(decision.chat_id,
                        "bundles are DM-only — the sealed file is your code, "
                        "and I don't post code into a group. open a DM: /link",
                        reply_to=decision.message_id, thread_id=decision.thread_id)
            return HandledResult(uid, "replied", "bundle-dm-only")
        if not self.bundle_passphrase:
            self._reply(decision.chat_id,
                        "no sealing key provisioned, so I refuse rather than "
                        "guess one. operator: store a passphrase as the "
                        "systemd credential `bundle_passphrase`.",
                        reply_to=decision.message_id, thread_id=decision.thread_id)
            return HandledResult(uid, "replied", "bundle-no-key")
        try:
            res = pack_github(cmd.arg, self.github_fetch, self.bundle_passphrase,
                              limits=self._pack_limits(),
                              token=self.config.github_token)
        except PackRefused as e:
            self._reply(decision.chat_id, f"bundle refused — {str(e)[:300]}",
                        reply_to=decision.message_id, thread_id=decision.thread_id)
            return HandledResult(uid, "replied", "bundle-refused")
        except (PackError, AuditDenied) as e:
            self._reply(decision.chat_id, f"no bundle — {str(e)[:200]}",
                        reply_to=decision.message_id, thread_id=decision.thread_id)
            return HandledResult(uid, "replied", "bundle-error")
        except Exception:
            self._reply(decision.chat_id, "no bundle — try again.",
                        reply_to=decision.message_id, thread_id=decision.thread_id)
            return HandledResult(uid, "replied", "bundle-error")
        try:
            self._send_document(decision.chat_id, res.filename(), res.blob,
                                caption=render_pack(res, max_len=1000),
                                thread_id=decision.thread_id,
                                boundary="----devin" + res.bundle_sha256[:16])
        except TelegramError as e:
            self._reply(decision.chat_id,
                        f"sealed ({res.files} files) but the upload failed: "
                        f"{str(e)[:200]}",
                        reply_to=decision.message_id, thread_id=decision.thread_id)
            return HandledResult(uid, "replied", "bundle-upload-error")
        return HandledResult(uid, "replied", f"bundle:{res.files}f")

    def _upload_refusal(self, decision, text, reason) -> HandledResult:
        self._reply(decision.chat_id, text, reply_to=decision.message_id,
                    thread_id=decision.thread_id)
        return HandledResult(decision.user_id if hasattr(decision, "user_id")
                             else None, "replied", reason)

    def _handle_document(self, uid, msg: dict, decision: AccessDecision) -> HandledResult:
        """Audit — and, when a sealing key exists, SEAL — an uploaded code set.

        This is the private-code path with no GitHub in it: whatever you have
        locally, compress it, send it, and get a static report back. When a
        sealing key is provisioned the same tree also comes back as ONE
        encrypted file, which is the "deploy encrypted onto any code set" story
        told honestly: a handoff artifact, not an execution or a deployment.

        Refusals, in order, all fail-closed: not a DM, disabled intake, bad
        filename/format/size, unusable file path from Telegram, download
        failure, actual bytes over the cap, magic-byte mismatch, unopenable
        archive. Nothing is executed at any point.
        """
        if (decision.chat_type or "").lower() != "private":
            return HandledResult(uid, "ignored", "upload-not-dm")
        if self.file_get is None:
            return self._upload_refusal(
                decision, "upload intake isn't wired up here — use /bundle "
                          "<github-url> for a repo, or ask the operator.",
                "upload-disabled")
        try:
            up = parse_document(msg, MAX_UPLOAD_BYTES)
        except UploadDenied as e:
            return self._upload_refusal(decision, str(e), "upload-refused")

        try:
            got = self._call("getFile", {"file_id": up.file_id})
        except TelegramError:
            return self._upload_refusal(decision, "telegram wouldn't hand me "
                                                  "that file. resend it?",
                                        "upload-getfile")
        path = safe_file_path((got.get("result") or {}).get("file_path"))
        if path is None:
            return self._upload_refusal(
                decision, "telegram returned a file path I won't follow — "
                          "refusing.", "upload-badpath")

        cap = download_cap(self.transport_max_bytes, MAX_UPLOAD_BYTES)
        try:
            resp = self.file_get(
                f"{TELEGRAM_API}/file/bot{self.config.token}/{path}",
                self.config.limits.http_timeout)
            data = resp.body or b""
        except Exception:
            return self._upload_refusal(decision, "the download failed — try "
                                                  "again.", "upload-fetch")
        if getattr(resp, "status", 0) != 200 or not data:
            return self._upload_refusal(decision, "the download came back "
                                                  "empty — try again.",
                                        "upload-empty")
        if len(data) > cap:
            return self._upload_refusal(
                decision, f"that unpacked to {len(data) // 1_048_576} MB; my cap "
                          f"is {cap // 1_048_576} MB.", "upload-toobig")
        if not sniff(up.kind, data):
            return self._upload_refusal(
                decision, "those bytes aren't really a "
                          f"{'zip' if up.kind == 'zip' else 'gzipped tarball'} — "
                          "I won't guess at a renamed file.", "upload-notarchive")

        root = None
        try:
            try:
                root, truncated = intake(up.kind, data, self._upload_limits())
            except UploadDenied as e:
                return self._upload_refusal(decision, str(e), "upload-unopenable")
            report = deep_tree_report(root, self._audit_limits(),
                                      owner="upload", repo=up.label(), ref="",
                                      truncated=truncated)
            sealed = None
            seal_note = ""
            if self.bundle_passphrase:
                try:
                    sealed = build_pack(root, self.bundle_passphrase,
                                        label=up.label().rsplit(".", 1)[0],
                                        limits=self._pack_limits())
                except PackRefused as e:
                    seal_note = f"\n\nnot sealed — {str(e)[:160]}"
                except Exception:
                    seal_note = "\n\nnot sealed — the packager failed."
            self._reply(decision.chat_id, render_deep_report(report) + seal_note,
                        reply_to=decision.message_id,
                        thread_id=decision.thread_id)
            if sealed is not None:
                try:
                    self._send_document(
                        decision.chat_id, sealed.filename(), sealed.blob,
                        caption=render_pack(sealed, max_len=1000),
                        thread_id=decision.thread_id,
                        boundary="----devin" + sealed.bundle_sha256[:16])
                except TelegramError:
                    self._reply(decision.chat_id,
                                "audited and sealed, but the upload back to "
                                "you failed.", reply_to=decision.message_id,
                                thread_id=decision.thread_id)
                    return HandledResult(uid, "replied", "upload-seal-failed")
            return HandledResult(uid, "replied",
                                 f"upload:{report.files_scanned}f"
                                 + (":sealed" if sealed is not None else ""))
        except Exception:
            self._reply(decision.chat_id, "that one failed to analyze — try "
                                          "resending it.",
                        reply_to=decision.message_id, thread_id=decision.thread_id)
            return HandledResult(uid, "replied", "upload-error")
        finally:
            cleanup(root)

    def _upload_limits(self) -> AnalysisLimits:
        L = self.config.limits
        return AnalysisLimits(max_files=max(200, L.max_repo_files * 4),
                             max_file_bytes=L.max_file_bytes,
                             max_total_bytes=L.max_total_bytes,
                             max_findings=max(200, L.max_findings * 4))

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
            self._reply(decision.chat_id, "Self-check failed.",
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
