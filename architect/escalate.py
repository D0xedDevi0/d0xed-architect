"""Escalation ladder: stay HTTP-first, render only when a page actually needs it.

The point of being HTTP-first is not paying for a browser on pages that do not
need one. But "HTTP-first" must not mean "broken on SPAs". So: fetch over HTTP
first (already paid for), *classify* what came back, and escalate to a real
browser only for the pages that came back as shells.

    http()  ->  looks_js_dependent()  ->  [render()]  ->  Response

Why classify instead of always rendering: on the measured bench, a browser
costs ~2.7x wall time and ~2x memory per page. Escalating on a minority of
pages keeps most of that back.

Robots/policy are NOT handled here — callers check access before fetching,
same as http.fetch(). This module only decides *how* to fetch.
"""
from __future__ import annotations

import re
import time

from .http import Response, UA, FetchError, DEFAULT_TIMEOUT

# ---------------------------------------------------------------- classification

# Markers that a page is a JS app shell rather than server-rendered content.
_SPA_MARKERS = (
    (r'id=["\']root["\']', "react#root"),
    (r'id=["\']app["\']', "vue#app"),
    (r'id=["\']__next["\']', "next#__next"),
    (r"__NEXT_DATA__", "next-data"),
    (r"window\.__NUXT__", "nuxt"),
    (r"ng-version=", "angular"),
    (r"window\.__remixContext", "remix"),
    (r'<div[^>]+id=["\'](?:mount|svelte)["\']', "svelte"),
)

_NOSCRIPT_ASK = re.compile(
    r"<noscript[^>]*>.{0,400}?(?:enable|required|javascript|turn on)",
    re.I | re.S)

_SCRIPT_SRC = re.compile(r"<script[^>]+src=", re.I)

# Tuned so a normal server-rendered page never escalates. See tests: the
# static-page case must score 0.
THIN_TEXT_CHARS = 400      # below this, with lots of HTML, it's a shell
SCRIPT_HEAVY_RATIO = 0.55  # script bytes / total bytes
ESCALATE_AT = 4            # score threshold


def visible_text(html: str) -> str:
    """Crude text extraction — only good enough to judge 'is there content'."""
    h = re.sub(r"<script\b.*?</script>", " ", html, flags=re.I | re.S)
    h = re.sub(r"<style\b.*?</style>", " ", h, flags=re.I | re.S)
    h = re.sub(r"<!--.*?-->", " ", h, flags=re.S)
    h = re.sub(r"<[^>]+>", " ", h)
    h = re.sub(r"&[a-z#0-9]{2,8};", " ", h, flags=re.I)
    return re.sub(r"\s+", " ", h).strip()


class Verdict:
    """Why we did (or did not) decide to render a page."""

    __slots__ = ("needs_render", "score", "reasons", "text_chars", "html_bytes")

    def __init__(self, needs_render: bool, score: float, reasons: list[str],
                 text_chars: int, html_bytes: int):
        self.needs_render = needs_render
        self.score = score
        self.reasons = reasons
        self.text_chars = text_chars
        self.html_bytes = html_bytes

    def __repr__(self) -> str:
        verdict = "RENDER" if self.needs_render else "http-ok"
        why = ", ".join(self.reasons) or "content present"
        return f"<Verdict {verdict} score={self.score:g} ({why})>"


def looks_js_dependent(resp: Response) -> Verdict:
    """Decide whether an HTTP response is a JS shell rather than content."""
    html = resp.text or ""
    reasons: list[str] = []
    score = 0.0

    body_bytes = len(html.encode("utf-8", "replace"))
    text = visible_text(html)
    text_chars = len(text)

    # A non-HTML body is never a render candidate (JSON, images, PDFs...).
    ct = (resp.content_type or "").lower()
    if ct and "html" not in ct:
        return Verdict(False, 0.0, ["non-html"], text_chars, body_bytes)

    # 1. Thin text but a big document: the classic shell signature.
    if text_chars < THIN_TEXT_CHARS:
        reasons.append(f"thin-text({text_chars}c)")
        score += 2
        if text_chars < 120:
            reasons.append("near-empty")
            score += 1

    # 2. Script-dominated payload.
    script_bytes = sum(len(m) for m in re.findall(
        r"<script\b.*?</script>", html, flags=re.I | re.S))
    if body_bytes and (script_bytes / body_bytes) > SCRIPT_HEAVY_RATIO:
        reasons.append(f"script-heavy({script_bytes * 100 // body_bytes}%)")
        score += 1.5

    # 3. SPA mount point.
    for pat, label in _SPA_MARKERS:
        if re.search(pat, html, re.I):
            reasons.append(label)
            score += 2
            break

    # 4. The page literally asks the user to enable JavaScript.
    if _NOSCRIPT_ASK.search(html):
        reasons.append("noscript-warning")
        score += 1.5

    # 5. Module scripts are only useful with JS execution.
    if _SCRIPT_SRC.search(html) and text_chars < THIN_TEXT_CHARS:
        reasons.append("script-src+thin")
        score += 0.5

    return Verdict(score >= ESCALATE_AT, score, reasons, text_chars, body_bytes)


# ---------------------------------------------------------------- rendering

_RENDER_LOCK_MSG = (
    "playwright not installed in this interpreter — "
    "pip install playwright (browser already on box)"
)


class RenderError(FetchError):
    pass


def render(url: str, timeout: int = DEFAULT_TIMEOUT,
           wait_until: str = "domcontentloaded",
           settle_ms: int = 350,
           user_agent: str = UA,
           max_bytes: int = 4_000_000) -> Response:
    """Fetch `url` through a real browser and return the post-JS DOM.

    Returns a normal Response (so callers need no special case), with
    `.rendered = True` set.
    """
    try:
        from playwright.sync_api import sync_playwright
    except Exception as e:  # pragma: no cover
        raise RenderError(_RENDER_LOCK_MSG) from e

    t0 = time.time()
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            try:
                ctx = browser.new_context(user_agent=user_agent)
                page = ctx.new_page()
                resp = page.goto(url, timeout=timeout * 1000,
                                 wait_until=wait_until)
                if settle_ms:
                    page.wait_for_timeout(settle_ms)
                html = page.content()
                final_url = page.url          # after any redirects
                status = resp.status if resp is not None else 0
                headers = dict(resp.headers) if resp is not None else {}
                ctype = headers.get("content-type", "text/html")
            finally:
                browser.close()
    except Exception as e:
        raise RenderError(f"render failed {url}: {e}") from e

    body = html.encode("utf-8", "replace")[:max_bytes]
    r = Response(url=final_url, status=status,
                 headers={k.lower(): v for k, v in headers.items()},
                 body=body, content_type=ctype,
                 elapsed_ms=int((time.time() - t0) * 1000))
    r.rendered = True
    return r


# ---------------------------------------------------------------- the ladder

class EscalationBudget:
    """Cap how often a single crawl may escalate, so one crawl can't melt."""
    __slots__ = ("max_renders", "used", "skipped")

    def __init__(self, max_renders: int = 25):
        self.max_renders = max_renders
        self.used = 0
        self.skipped = 0

    def spend(self) -> bool:
        if self.used >= self.max_renders:
            self.skipped += 1
            return False
        self.used += 1
        return True

    @property
    def exhausted(self) -> bool:
        return self.used >= self.max_renders


def fetch_smart(url: str, *, timeout: int = DEFAULT_TIMEOUT,
                agent_id: str | None = None,
                allow_render: bool = True,
                force_render: bool = False,
                budget: EscalationBudget | None = None,
                wait_until: str = "domcontentloaded") -> tuple[Response, Verdict]:
    """HTTP-first, escalating to a browser only when the page needs it.

    Returns (response, verdict) so callers get the real content *and* the
    reason it took the path it did — which is what makes crawl reports
    honest about how many pages actually needed rendering.
    """
    from .http import fetch

    resp = fetch(url, timeout=timeout, agent_id=agent_id)

    if force_render:
        if budget is not None and not budget.spend():
            return resp, Verdict(False, 0.0, ["budget-exhausted"],
                                 len(visible_text(resp.text or "")),
                                 len(resp.body or b""))
        return render(url, timeout=timeout, wait_until=wait_until), \
            Verdict(True, 99.0, ["forced"], 0, 0)

    verdict = looks_js_dependent(resp)
    if not verdict.needs_render or not allow_render:
        return resp, verdict

    if budget is not None and not budget.spend():
        verdict.reasons.append("budget-exhausted")
        return resp, verdict

    rendered = render(url, timeout=timeout, wait_until=wait_until)
    return rendered, verdict
