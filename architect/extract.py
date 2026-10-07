"""HTML -> structured, LLM-ready data. Stdlib only (no bs4 dependency)."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from html.parser import HTMLParser

SKIP = {"script", "style", "noscript", "svg", "template", "iframe"}
BLOCK = {"p", "div", "section", "article", "li", "br", "tr", "h1", "h2", "h3",
         "h4", "h5", "h6", "blockquote", "pre"}


@dataclass
class Page:
    url: str = ""
    title: str = ""
    description: str = ""
    canonical: str = ""
    lang: str = ""
    headings: list = field(default_factory=list)      # (level, text)
    links: list = field(default_factory=list)         # (href, text)
    code_blocks: list = field(default_factory=list)
    emails: list = field(default_factory=list)
    json_ld: list = field(default_factory=list)
    forms: int = 0
    scripts: int = 0
    word_count: int = 0
    text: str = ""
    hidden_suspicious: list = field(default_factory=list)


class _Extractor(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.p = Page()
        self._skip = 0
        self._in_title = False
        self._in_code = False
        self._h: str | None = None
        self._buf: list[str] = []
        self._code: list[str] = []
        self._text: list[str] = []
        self._link_href = None
        self._link_text: list[str] = []
        self._in_jsonld = False
        self._jsonld: list[str] = []
        self._style_attr_stack: list[str] = []

    # -- helpers
    def _hidden(self, attrs: dict) -> bool:
        style = (attrs.get("style") or "").replace(" ", "").lower()
        if not style:
            return False
        if "display:none" in style or "visibility:hidden" in style:
            return True
        if re.search(r"font-size:0", style) or "opacity:0" in style:
            return True
        return False

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag in SKIP:
            if tag == "script" and a.get("type", "").lower() == "application/ld+json":
                self._in_jsonld = True
            else:
                self._skip += 1
            if tag == "script":
                self.p.scripts += 1
            return
        if self._skip:
            return
        if tag == "title":
            self._in_title = True
        elif tag == "html":
            self.p.lang = a.get("lang", "")
        elif tag == "meta":
            n = a.get("name", "").lower() or a.get("property", "").lower()
            if n in ("description", "og:description"):
                self.p.description = self.p.description or a.get("content", "")
        elif tag == "link" and "canonical" in a.get("rel", "").lower():
            self.p.canonical = a.get("href", "")
        elif tag in ("h1", "h2", "h3", "h4", "h5", "h6"):
            self._h = tag
            self._buf = []
        elif tag == "a":
            self._link_href = a.get("href", "")
            self._link_text = []
        elif tag in ("pre", "code"):
            self._in_code = True
            self._code = []
        elif tag == "form":
            self.p.forms += 1
        if self._hidden(a):
            self.p.hidden_suspicious.append(f"<{tag}> {a.get('class') or a.get('id') or ''}")
        if tag in BLOCK:
            self._text.append("\n")

    def handle_endtag(self, tag):
        if tag == "script" and self._in_jsonld:
            self._in_jsonld = False
            blob = "".join(self._jsonld).strip()
            self._jsonld = []
            if blob:
                try:
                    self.p.json_ld.append(json.loads(blob))
                except Exception:
                    pass
            return
        if tag in SKIP:
            self._skip = max(0, self._skip - 1)
            return
        if self._skip:
            return
        if tag == "title":
            self._in_title = False
            self.p.title = " ".join("".join(self._buf).split())
        elif tag in ("h1", "h2", "h3", "h4", "h5", "h6") and self._h:
            txt = " ".join("".join(self._buf).split())
            if txt:
                self.p.headings.append((int(self._h[1]), txt))
            self._h = None
        elif tag == "a" and self._link_href is not None:
            self.p.links.append((self._link_href,
                                 " ".join("".join(self._link_text).split())))
            self._link_href = None
        elif tag in ("pre", "code") and self._in_code:
            blob = "".join(self._code).strip()
            if len(blob) > 24:
                self.p.code_blocks.append(blob[:4000])
            self._in_code = False
        if tag in BLOCK:
            self._text.append("\n")

    def handle_data(self, data):
        if self._in_jsonld:
            self._jsonld.append(data)
            return
        if self._skip:
            return
        self._buf.append(data)
        if self._in_code:
            self._code.append(data)
        if self._link_href is not None:
            self._link_text.append(data)
        self._text.append(data)

    def finish(self, url: str) -> Page:
        self.p.url = url
        text = re.sub(r"[ \t\r\f\v]+", " ", "".join(self._text))
        text = re.sub(r"\n\s*\n\s*\n+", "\n\n", text).strip()
        self.p.text = text
        self.p.word_count = len(text.split())
        self.p.emails = sorted(set(re.findall(
            r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", text)))
        return self.p


def extract(html: str, url: str) -> Page:
    p = _Extractor()
    try:
        p.feed(html)
    except Exception:
        pass
    return p.finish(url)


def to_markdown(page: Page) -> str:
    lines = []
    if page.title:
        lines.append(f"# {page.title}")
    if page.description:
        lines.append(f"\n> {page.description}")
    used = set()
    for lvl, txt in page.headings:
        lines.append(f"\n{'#' * min(lvl + 1, 6)} {txt}")
        used.add(txt)
    lines.append("\n" + page.text[:6000])
    return "\n".join(lines)
