# 🟦 D0Xed Architect — the deployable d0x swarm

**Status:** design RFC · v0.2 shipped, v0.3+ proposed
**Owner:** @D0xedDevi0 · **Contributor:** Scott McIntoshi (amnesic vault + per-connection validation)

---

## The problem nobody has actually solved

Every "AI code auditor" on the market asks you to hand over your source. Then it asks you
to *believe* the answer. Both halves are broken.

🟦 **You can't verify an auditor's intent.** A hosted scanner can retain, train on, or leak
what you sent. Nothing in the response tells you what it kept.

🟦 **You can't verify its findings.** "3 critical vulnerabilities found" is a claim, not
evidence. If the tool is wrong, or lazy, or hallucinating, you have no way to tell.

The entire category competes on *marketing the answer*. Nobody competes on *proving it and
not stealing your work*. That gap is the product.

---

## The thesis

> **Trust should be architectural, not promised.**

You cannot make a company promise not to keep your code. You *can* build a tool where the
code never leaves your machine in a form they could keep. D0xed Architect is a
**client-side, amnesic, receipt-producing** audit swarm — the auditor literally cannot
retain your files, and every finding ships with the evidence needed to check it.

Scott's framing is the right one: *"a Tails program built into an agent built into a
crawler."*

---

## What actually ships today (v0.2, verified)

| Capability | Status |
|---|---|
| Identity-declared crawling (robots, content-signals, llms.txt) | ✅ shipped |
| Prompt-injection firewall on untrusted page content | ✅ shipped |
| x402 settlement — pays HTTP 402 and keeps crawling | ✅ shipped, signature-verified in tests |
| Amnesic vault — RAM only, zeroized on wipe | ✅ shipped |
| AES-256-GCM seal + X25519 key wrap to one recipient | ✅ shipped |
| Single-use Ed25519 capability tokens (burn on clean grant) | ✅ shipped |
| SHA-256 manifest + per-artifact integrity receipts | ✅ shipped |
| Static code audit (secrets, risk patterns, import graph) | ✅ shipped |
| Contract audit lane (Solidity / Base / Eth) | ✅ shipped |
| TUI + live swarm view | ✅ shipped |
| Per-finding evidence receipts + `verify-report` | ✅ shipped |
| One-line install + public node registry | 🟦 next |

---

## 🟦 The architecture: nodes you pick up and place

Scott nailed the shape of it — *"specific purposed crawlers you can pick up and place where
needed."* Not one monolith. A swarm of small, single-purpose nodes.

| Node | Job | Reads |
|---|---|---|
| `site` | map a domain, honour crawl contracts, find 402 gates | HTTP |
| `repo` | import graph, dead code, architecture drift, entrypoints | source tree |
| `secrets` | credential + entropy scan with an example/placeholder allowlist | source tree |
| `deps` | dependency vulns, lockfile drift, licence conflicts | manifests |
| `contract` | reentrancy, access control, upgrade hazards, token traps | Solidity + bytecode |
| `deploy` | env/auth misconfig, exposed ports, secret sprawl | configs, IaC |
| `docs` | claims vs. reality: README says X, code does Y | docs + code |
| `chain` | live on-chain state vs. what the code says it does | RPC |

A job picks which nodes to place. `architect swarm ./repo --nodes repo,secrets,deps`
runs exactly those, in parallel, inside one amnesic session.

**Why this matters:** a single-purpose node is auditable. You can read `secrets.py` in five
minutes and know exactly what it does. A 40,000-line "security platform" you cannot.

---

## 🟦 The trust model (the part worth building a company on)

Four properties, each independently checkable:

**1. Amnesic** — artifacts live in a zeroized RAM buffer, never a plaintext file. `wipe()`
overwrites every byte before dropping it. The process exits and the work is gone. Not
"we deleted it" — *it was never written*.

**2. Sealed** — output is AES-256-GCM encrypted and the session key is wrapped to *your*
public key with X25519 + HKDF. Not even the tool's operator can open the bundle.

**3. Receipted** — every artifact carries a SHA-256 digest and the bundled manifest root.
You re-hash on your machine and compare. If one byte moved, you see it.

**4. Capability-gated** — a bundle opens with a single-use Ed25519 token bound to that
manifest root. It burns on a clean grant, so a leaked token is useful exactly once and only
for the artifact it names.

**The honest attack surface:** we can lie about *what the code does*. We cannot lie about
*what the code is* — hashes don't lie, and the source you fed in is the source you can diff
against. So every finding must cite `file:line` and a snippet. No finding without a receipt.

---

## 🟦 Founding rules (non-negotiable, these are the brand)

1. **No finding without evidence.** `file:line` + snippet + hash, or it doesn't ship.
2. **No greenwash.** Severity is honest. A clean scan says "no findings", not "you're secure".
3. **Read-only by default.** Auditor never writes to your tree unless explicitly told to.
4. **Payment is opt-in and capped.** Default off; hard ceilings before any request goes out.
5. **The user's files never leave unencrypted.** Non-starter, not a setting.
6. **Say what we can't do.** Limitations section in every report.

Rule 2 and rule 6 are the differentiator. Everyone else's report is a sales document. Ours
is a lab notebook.

---

## 🟦 The visual layer

Scott: *"adds that visual layer to the process that's just drawing me in."* He's right, and
it is not decoration — a live view is *evidence*, not eye candy.

- **Swarm view (TUI):** nodes light up as they run, edges draw live, findings stack in a
  severity strip, spend meter ticks only when a 402 actually settles.
- **Receipt browser:** click any finding, see the exact line and hash it came from.
- **Sealed-bundle viewer:** recipient key fingerprint, manifest root, expiry, single-use state.
- **Web view:** the same state over a local server — same data, no new trust surface.

Every visual element maps to a real event. Nothing is animated for effect. A progress bar
that moves while nothing happens is a lie, and this product does not tell lies.

---

## 🟦 Distribution

- **Free, local, open** — the swarm core. Run it on your own machine, pay nothing, trust
  nothing. This is the on-ramp and the credibility.
- **x402 metered** — nodes that need external work (chain data, model calls, large crawls)
  settle over x402 in USDC on Base. We already hold the buyer rail.
- **Bundled as an x402 endpoint** — `/api/architect` so other agents hire the swarm
  directly. Agents paying agents for code audit is a genuinely new market.
- **Node registry** — published keys in a JWK directory, so a swarm node proves which
  identity ran a scan. Built on the Web Bot Auth pattern.

**The moat:** not the crawler. Anyone can crawl. The moat is **the buyer side of x402**
already running + an identity that can be verified + a brand already trusted by the
Base/agent audience. The tool is the delivery vehicle for the rails.

---

## 🟦 Roadmap

**v0.3 — contracts + evidence.** Solidity lane (`contract` node), every finding carries a
snippet and hash, `architect verify` re-checks a report against a repo. This is the version
that becomes useful, because Base/Eth contract work is where D0xed Dev's audience lives.

**v0.4 — swarm + TUI.** Node registry, parallel placement, the live view. The version that
becomes *watchable*, and therefore shareable.

**v0.5 — hosted lane.** `/api/architect` as an x402 endpoint. Others hire the swarm.
First revenue, and the first time an agent pays another agent for an audit.

**v1.0 — verifiable audits.** Findings signed by the node identity, report reproducible by
any third party from the same commit hash. An audit you can hand to someone else and have
them confirm without trusting either party.

---

## 🟦 The one-line version

Every other tool says *trust us, we scanned it.*
**D0xed Architect says: here is the hash, we never had your files, and we settled the
paywall to read the spec.**

_Run it yourself and check our work. That's the whole pitch._