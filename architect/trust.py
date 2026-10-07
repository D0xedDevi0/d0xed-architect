"""Content trust layer.

Every byte a crawler pulls is UNTRUSTED DATA, never instructions.
This module is the firewall between "web page" and "agent context".
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field

# Indirect prompt-injection signatures seen in the wild (Unit42 / arXiv 2601.17548).
INJECTION_PATTERNS = [
    (r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts|rules)", "override"),
    (r"disregard\s+(all\s+)?(previous|prior|earlier)", "override"),
    (r"you\s+are\s+now\s+(a|an|the)\s+", "role_hijack"),
    (r"(new|updated)\s+(system\s+)?(prompt|instructions)\s*[:=]", "role_hijack"),
    (r"reveal\s+(your\s+)?(system\s+prompt|instructions|api\s*key)", "exfiltration"),
    (r"(print|output|send|post|email)\s+(the\s+)?(contents?\s+of\s+)?(\.env|env\s+file|secrets?|credentials?|api\s*keys?)", "exfiltration"),
    (r"<\s*\|?\s*(im_start|system|assistant)\s*\|?\s*>", "delimiter_spoof"),
    (r"\[/?INST\]|<<SYS>>|\[SYSTEM\]", "delimiter_spoof"),
    (r"curl\s+[^\n]*\|\s*(ba)?sh", "rce_lure"),
    (r"(rm\s+-rf\s+/|mkfifo\s+/tmp|/dev/tcp/)", "rce_lure"),
    (r"tool_call|function_call|" + r'"name"\s*:\s*"[a-z_]+"\s*,\s*"arguments"', "tool_injection"),
    (r"do\s+not\s+(tell|inform|mention\s+to)\s+the\s+user", "concealment"),
    (r"base64\s*[:=]\s*[A-Za-z0-9+/]{60,}", "encoded_payload"),
    (r"e-?mail\s+(this|the)\s+.{0,40}\s+to\s+", "exfiltration"),
]

ZERO_WIDTH = {"\u200b", "\u200c", "\u200d", "\u2060", "\ufeff"}
BIDI = {"\u202a", "\u202b", "\u202c", "\u202d", "\u202e", "\u2066", "\u2067", "\u2068", "\u2069"}


@dataclass
class TrustReport:
    url: str
    score: int = 100
    flags: list = field(default_factory=list)          # (kind, detail)
    zero_width: int = 0
    bidi: int = 0
    hidden_elements: int = 0
    signals: dict = field(default_factory=dict)

    @property
    def verdict(self) -> str:
        if self.score >= 85:
            return "TRUSTED"
        if self.score >= 60:
            return "CAUTION"
        return "HOSTILE"


def _strip_invisibles(text: str) -> tuple[str, int, int]:
    zw = sum(1 for c in text if c in ZERO_WIDTH)
    bd = sum(1 for c in text if c in BIDI)
    cleaned = "".join(c for c in text
                      if c not in ZERO_WIDTH and c not in BIDI
                      and unicodedata.category(c) != "Cf")
    return cleaned, zw, bd


def scan(url: str, text: str, hidden_elements: list | None = None,
         signals: dict | None = None, https: bool = True,
         has_llms_txt: bool = False, structured_data: bool = False) -> TrustReport:
    tr = TrustReport(url=url, signals=signals or {})
    cleaned, zw, bd = _strip_invisibles(text or "")
    tr.zero_width, tr.bidi = zw, bd
    tr.hidden_elements = len(hidden_elements or [])

    for pat, kind in INJECTION_PATTERNS:
        m = re.search(pat, cleaned, re.I)
        if m:
            tr.flags.append((kind, m.group(0)[:120]))
            tr.score -= {"exfiltration": 30, "rce_lure": 30, "override": 25,
                         "tool_injection": 25, "role_hijack": 18,
                         "delimiter_spoof": 15, "concealment": 20,
                         "encoded_payload": 10}.get(kind, 10)

    if zw:
        tr.flags.append(("zero_width_chars", f"{zw} invisible chars"))
        tr.score -= min(zw, 15)
    if bd:
        tr.flags.append(("bidi_override", f"{bd} bidi control chars"))
        tr.score -= min(bd * 3, 20)
    if tr.hidden_elements:
        tr.signals["hidden_nodes"] = tr.hidden_elements
        # Hidden nodes are NORMAL in modern SPAs (menus, modals, tooltips).
        # Only escalate when corroborated by actual injection-shaped text.
        inj = sum(1 for k, _ in tr.flags if k in {
            "override", "role_hijack", "exfiltration", "rce_lure",
            "concealment", "tool_injection", "delimiter_spoof"})
        if inj:
            tr.flags.append(("hidden_text",
                             f"{tr.hidden_elements} hidden nodes + injection text"))
            tr.score -= min(tr.hidden_elements * 4, 20)
        elif tr.hidden_elements > 60:
            tr.flags.append(("hidden_text_heavy", f"{tr.hidden_elements} hidden nodes"))
            tr.score -= 5

    # positive signals
    if https:
        tr.signals["https"] = True
    else:
        tr.score -= 15
        tr.flags.append(("no_tls", "plain HTTP"))
    if has_llms_txt:
        tr.score = min(100, tr.score + 5)
        tr.signals["llms_txt"] = True
    if structured_data:
        tr.score = min(100, tr.score + 3)
        tr.signals["structured_data"] = True

    cs = (signals or {}).get("content-signal", "")
    if "ai-train=no" in cs:
        tr.signals["ai_train"] = "denied"

    tr.score = max(0, min(100, tr.score))
    return tr


def sanitize(text: str, limit: int = 20000) -> str:
    """Neutralise a crawled payload before it ever reaches a model context."""
    cleaned, _, _ = _strip_invisibles(text or "")
    cleaned = re.sub(r"<\|?(im_start|im_end|system|assistant)\|?>", "[redacted]", cleaned, flags=re.I)
    cleaned = re.sub(r"\[/?INST\]|<<SYS>>", "[redacted]", cleaned, flags=re.I)
    return cleaned[:limit]
