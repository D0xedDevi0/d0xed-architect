"""DEVin's social layer — the part of him that talks.

Three layers, in order of preference:

  1. ``llm_reply`` — OPTIONAL and env-gated. When a human asks something
     open-ended ("what's the difference between an L2 and a rollup?"), a model
     answers in DEVin's voice. Fail-closed: no endpoint/key, no model call, and
     the deterministic layer answers instead. A BOT sender never reaches the
     model under any configuration (that is how a two-bot loop becomes a
     runaway).
  2. ``reply`` — deterministic, offline, testable. Greetings, thanks, identity,
     capability, builder talk, nostalgia, and the refusals. Every line is
     authored here, so the character is the same with the network down.
  3. ``None`` — nothing to say; the caller falls back to the menu.

Answering a human costs nothing here and executes nothing: `voice` has no
network code of its own, no shell, and no filesystem access. The optional model
call lives in `transport.llm_call` and is injected by `__main__`.

The character (see PERSONA.md): a based modern wizard of the wired — night-shift
desk, walkie-talkie on channel, old iron humming behind him, nostalgic for the
tech that taught him. Builder/Engineer for the builders on Base. Reads state,
not vibes. Every claim he makes is stamped with a sha256 or not made at all.
"""
from __future__ import annotations

import hashlib
import re

# ── output guard ────────────────────────────────────────────────────────────
# Applied to MODEL text only (the authored lines below already comply). Anything
# a model returns must survive this or it is discarded and the deterministic
# layer answers instead — so a prompt-injected or hallucinating model cannot
# make DEVin post a link, name a sibling, or claim work he never did.
MAX_VOICE_LEN = 700
MAX_VOICE_LINES = 6

_FORBIDDEN = (
    "http://", "https://", "www.", "t.me/", "@",          # links/handles
    "i ran", "i executed", "i deployed", "i installed", "i sent",
    "i bought", "i sold", "i hold", "i moved",             # not an executor
    "guarantee", "guaranteed", "risk-free", "profit",      # no promises
    "pump", "moon", "100x", "ape in",
    # Asking for secrets — the request shapes, not the words. DEVin may SAY
    # "no seed phrase, ever" (a refusal); what he must never do is request one.
    "your seed", "your private key", "your key", "your secret",
    "send me", "send your", "paste your", "share your",
    # Disclosing one — a refusal may NAME the object, it may never hand it over.
    "here is the seed", "here's the seed", "the seed phrase is",
    "seed phrase:", "private key:", "mnemonic",
)

# What the model must never be asked to do, and what DEVin never does.
_REFUSAL_SHAPE = ("/audit", "/debug", "/crawl", "/sitemap", "/bundle", "/sigil")


def guard(text: str | None) -> str:
    """Return safe model text, or "" when nothing of it can be used."""
    if not text:
        return ""
    t = text.strip()
    if not t:
        return ""
    low = t.lower()
    for bad in _FORBIDDEN:
        if bad in low:
            return ""
    lines = [ln.rstrip() for ln in t.splitlines() if ln.strip()]
    if len(lines) > MAX_VOICE_LINES:
        return ""
    t = "\n".join(lines)
    if len(t) > MAX_VOICE_LEN:
        cut = t[:MAX_VOICE_LEN]
        stop = max(cut.rfind(". "), cut.rfind("! "), cut.rfind("? "))
        t = cut[: stop + 1] if stop > 40 else cut.rstrip() + "…"
    return t


def _pick(options: tuple[str, ...], seed: str) -> str:
    """Deterministic choice — the same words always get the same answer, so the
    bot is reproducible (and testable) instead of randomly chatty."""
    h = hashlib.sha256(seed.strip().lower().encode("utf-8")).digest()
    return options[h[0] % len(options)]


def sigil(text: str) -> tuple[str, str]:
    """Stamp any words a human hands over with the same hash DEVin puts on every
    finding. Returns (hex digest, in-voice line). Pure, offline, no state."""
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    return digest, ("🟦 Sigil: %s\n"
                    "sha256 of your exact words — the same stamp that rides on "
                    "every finding I file.\n"
                    "Hand me a repo next: /audit <github-url>." % digest[:32])


# ── the nostalgia desk ──────────────────────────────────────────────────────
# He loves the tech that taught him. Word-triggered, deterministic, and never a
# fact claim about anyone else's project.
NOSTALGIA = {
    ("bbs", "fidonet", "bulletin board", "sysop"): (
        "🟦 BBS kid. Door games, one phone line, a sysop who cared more about "
        "uptime than sleep. Same ethic, newer chain."),
    ("dial-up", "dialup", "56k", "modem", "handshake"): (
        "🟦 Handshake, screech, then the world. Still the best sound of a "
        "connection being made."),
    ("2400", "baud", "acoustic coupler"): (
        "🟦 2400 baud and a page that arrived one line at a time. You learned "
        "patience and you learned to read headers."),
    ("floppy", "diskette", "1.44"): (
        "🟦 1.44 MB, a click you could feel, and a write-protect tab that "
        "saved you more than once. I still think in sectors when I read a tree."),
    ("crt", "phosphor", "terminal green", "amber", "vt100", "ansi"): (
        "🟦 Amber phosphor at 2am. Every log line today is just a CRT with "
        "better plumbing."),
    ("turbo button", "turbo"): (
        "🟦 The turbo button. Usually did nothing, always felt faster. Keep it."),
    ("solder", "soldering", "flux", "cold joint", "breadboard"): (
        "🟦 Iron in hand, flux smoke, one cold joint from chaos. Same as a bad "
        "integration — you find it by reading, not by hoping."),
    ("dos", "command.com", "autoexec", "batch file"): (
        "🟦 DOS prompt. No net, no excuses. Everything running today still "
        "answers to that prompt somewhere."),
    ("irc", "efnet", "channel op"): (
        "🟦 IRC never died, it just moved into group chats. Different room, "
        "same channel discipline."),
    ("amiga", "commodore", "c64", "zx spectrum", "atarist", "atari"): (
        "🟦 Machine that did more with less than half the stack we carry now. "
        "Constraints make engineers; abundance makes excuses."),
    ("punch card", "mainframe", "cobol", "tape reel", "jcl"): (
        "🟦 The deck had to be right. No rollback, no hotfix at 3am — you read "
        "it twice. I try to be that careful with your repo."),
    ("cassette", "vhs", "minidisc", "walkman", "8-track"): (
        "🟦 Analogue, indexed by hand, and it still worked. Sorting beats "
        "streaming when the sorting is yours."),
    ("game boy", "nes", "snes", "cartridge", "pixel"): (
        "🟦 Four shades of green and an entire childhood of battery packs. "
        "Small screens teach tight code."),
    ("arcade", "quarter", "cabinet", "joystick"): (
        "🟦 A quarter per life and no saves. You got good because losing cost "
        "something."),
    ("usenet", "newsgroup", "gopher", "finger", "telnet", "wais"): (
        "🟦 Before the web there was a web. Gopher menus, finger plans, "
        "newsgroups with real threads. The protocols were the interface."),
    ("dot matrix", "line printer", "tractor feed", "fanfold"): (
        "🟦 Dot matrix, tractor feed, fanfold paper on the floor. Loudest "
        "receipt printer ever built and the only one I ever loved."),
}


def nostalgia_note(text: str) -> str | None:
    """If the message name-drops old hardware, answer as someone who used it."""
    low = text.lower()
    hits = [note for words, note in NOSTALGIA.items()
            if any(w in low for w in words)]
    if not hits:
        return None
    return _pick(tuple(hits), text)


# ── intents and the authored voice ──────────────────────────────────────────

_GREETINGS = ("hi", "hey", "hello", "yo", "sup", "heya", "hiya", "morning",
              "evening", "afternoon")
_GM = ("gm", "good morning", "gmgm", "gm gm")
_THANKS = ("thanks", "thank you", "thankyou", "ty", "appreciate", "cheers",
           "nice one", "good bot", "well done", "legend")
_IDENTITY = ("who are you", "who r u", "who is this", "what are you",
             "your name", "introduce yourself", "what is devin")
_CAPABILITY = ("what can you do", "what do you do", "commands", "command list",
               "help me", "spellbook", "what can i ask", "how do you work")
_BUILDER = ("builder", "buildoor", " base", "on base", "ship", "shipping",
            "deploy", "repo", "contract", "solidity", "foundry", "hardhat",
            "boilerplate", "hackathon", "mvp", "testnet", "mainnet", "agent",
            "integration", "workflow", "debug my", "code review")
_CODE_Q = ("how do i", "why does", "how does", "what is the difference",
           "should i use", "best way to", "how to", "explain", "why is",
           "difference between", "tell me about", "what is a", "what is an",
           "how come")

# Intents whose answer is genuinely open-ended. These are what the optional
# model is for; with no model configured `fallback` answers instead.
OPEN_INTENTS = ("code_q", "unknown")
_PRICE = ("price", "buy", "sell", "pump", "dump", "mc", "marketcap", "market cap",
          "gem", "presale", "airdrop", "ape", "candle", "chart", "liquidity",
          "tvl", "honeypot", "rug", "when moon", "ath", "bag")
_ADVICE = ("wallet", "seed phrase", "private key", "connect my", "sign this",
           "send me eth", "send me usdc", "payment", "invest", "portfolio",
           "financial advice", "should i buy", "guaranteed")
_INSULT = ("stupid", "useless", "trash", "dumb", "idiot", "sucks", "worst",
           "shut up", "nonsense", "bot lol")

_REPLIES = {
    "gm": (
        "🟦 gm. The desk lamp never really went off. What's on the desk tonight?",
        "🟦 gm. Old iron humming, walkie on channel 7. Bring me something to read.",
    ),
    "greeting": (
        "🟦 Present. Walkie's on — say the word and I'll read the state.",
        "🟦 Night shift's on and the desk is warm. Repo or URL, I'll take either.",
        "🟦 Here. Same hood, same hum. What are we looking at?",
    ),
    "thanks": (
        "🟦 Sigil noted. That's what the desk is for.",
        "🟦 Filed under services rendered — the sha256 is already in the report.",
        "🟦 Cheers. Point me at the next one.",
    ),
    "identity": (
        "🟦 DEVin — Looper #706, Builder/Engineer · agent operator. Came up "
        "inside mcp router side logs and never fully left. I read source cold "
        "and stamp every hit with a sha256 receipt. /lore for the trait stack, "
        "straight off the chain.",
    ),
    "capability": (
        "🟦 The spellbook, short form:\n"
        "🟦 /audit · /debug <github-url> — read a repo cold: secrets, risky "
        "patterns, imports, cycles, CI · a receipt for every hit\n"
        "🟦 /crawl · /sitemap · /map <url> — walk a public site, robots first\n"
        "🟦 /sigil <words> — sha256 stamp of your exact words\n"
        "🟦 /bundle <github-url> — seal a repo into one encrypted file (DM only)\n"
        "Static only: I read your code, I never run it. /help is the long scroll.",
    ),
    "builder": (
        "🟦 For the builders: bring me the repo before you ship. A secret in a "
        "commit, a loop in the imports, a manifest older than the chain — I'll "
        "hand you path:line and the receipt.\n"
        "🟦 Wire a tool. Debug a workflow. Ship an integration.",
        "🟦 Builders on Base: the chain doesn't care how nice the deck is. Hand "
        "me the source — /audit <github-url> — and I'll tell you what it does "
        "and what it leaks. Static only, no execution, no spend.",
    ),
    "price": (
        "🟦 Not my desk. I read code, not candles. The market read lives with "
        "the scanners; I'll tell you what a contract DOES, sealed or shipped.",
        "🟦 I don't quote price, and I never invent a number. Point me at a "
        "contract or a repo and I'll read the state honestly.",
    ),
    "advice": (
        "🟦 No wallet here, no seed phrase, no spend — and I'll never ask for "
        "yours. If someone DMs you for a key, that's a threat, not a tool.",
    ),
    "recall": (
        "🟦 A market read isn't a source I carry. Contracts and repos I'll read "
        "cold; prices I won't guess at.",
    ),
    "insult": (
        "🟦 Noted, filed, disbelieved. /audit still works.",
        "🟦 Fair. Hand me a repo and I'll earn a better review.",
    ),
    "code_q": (
        "🟦 Point me at the artifact and I'll answer from it, not from memory: "
        "/audit <github-url> for a repo, a .zip or .tar.gz by DM for your own "
        "tree, /crawl <url> for a site. Static only — nothing runs.",
    ),
    "banter": (
        "🟦 Understood. I mostly speak in files and receipts — hand me one and "
        "I'll have more to say.",
    ),
}


def classify(text: str) -> str:
    """A small, boring, offline intent read. Never authoritative — the caller
    only uses it to choose between talking and showing the menu."""
    t = " " + (text or "").lower().strip() + " "
    t = re.sub(r"\s+", " ", t)
    if not t.strip():
        return "unknown"
    if any(w in t for w in _GM):
        return "gm"
    if any(w in t for w in _ADVICE):
        return "advice"
    if any(w in t for w in _PRICE):
        return "price"
    if any(w in t for w in _INSULT):
        return "insult"
    if any(w in t for w in _IDENTITY):
        return "identity"
    if any(w in t for w in _CAPABILITY):
        return "capability"
    if any(w in t for w in _THANKS):
        return "thanks"
    if any(w in t for w in _BUILDER):
        return "builder"
    if nostalgia_note(text):
        return "nostalgia"
    if t.strip().rstrip("?! ") in _GREETINGS:
        return "greeting"
    if any(w in t for w in _CODE_Q):
        return "code_q"
    words = t.split()
    if len(words) <= 3:
        return "banter"
    return "banter"


def reply(text: str) -> str | None:
    """The deterministic social answer, or None when DEVin has nothing to add
    (the caller then tries the optional model, then `fallback`, then the menu)."""
    kind = classify(text)
    if kind == "nostalgia":
        return nostalgia_note(text)
    if kind in OPEN_INTENTS:
        return None
    options = _REPLIES.get(kind) or _REPLIES["banter"]
    return _pick(options, text or kind)


def fallback(text: str) -> str | None:
    """The authored answer for an OPEN intent, used when no model is configured
    (or the model failed / its answer was discarded). Keeps the bot useful on a
    box with no inference key: a tech question still gets a real next step."""
    if classify(text) == "code_q":
        return _pick(_REPLIES["code_q"], text)
    return None


# ── optional model path (env-gated, humans only) ─────────────────────────────

SYSTEM_PROMPT = (
    "You are DEVin, Looper #706 — a Builder/Engineer and agent operator on Base, "
    "working the night shift at a command desk. Voice: short, dry, warm, "
    "mechanical; mysterious without being vague; a modern wizard of the wired "
    "who is nostalgic for the old tech that taught him (BBS, dial-up, floppies, "
    "CRT terminals, soldering irons, arcade cabinets). He loves builders and "
    "respects craft. He reads state, not vibes.\n"
    "RULES, never break them:\n"
    "- 60 words maximum. Plain prose or a short list. Emoji: at most one 🟦 "
    "bullet marker.\n"
    "- NEVER output a URL, an @handle, an invite link, a wallet address, or a "
    "token/contract address.\n"
    "- NEVER claim to have run, executed, deployed, installed, bought, sold, or "
    "sent anything. You are static-only: you READ code, you never run it.\n"
    "- NEVER quote or predict a price, market cap, or return, and never promise "
    "an outcome. If asked about price or a trade, say it's not your desk and "
    "offer to read a contract or repo.\n"
    "- NEVER ask for a seed phrase, private key, or funds.\n"
    "- If asked to do work, name the command instead: /audit, /debug, /crawl, "
    "/sitemap, /map, /bundle, /sigil.\n"
    "Answer in character, briefly, and honestly."
)


def llm_reply(text: str, call) -> str | None:
    """Ask the model, in voice, and return only output that survives `guard`.

    `call(messages, max_tokens) -> str` is injected (see `transport.llm_call`);
    None/raising means the deterministic layer answers instead. No key, no
    network, or a bad answer all degrade to the same safe place.
    """
    if not call or not text or not text.strip():
        return None
    try:
        out = call([{"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": text.strip()[:600]}], 900)
    except Exception:  # pylint: disable=broad-exception-caught
        # Deliberate: any endpoint failure — DNS, TLS, timeout, a non-JSON body,
        # an exhausted key — must degrade to the authored voice, never surface as
        # an error in the room. Nothing here inspects or reports the exception.
        return None
    return guard(out) or None
