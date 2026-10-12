# DEVin / Looper #706 — read-only activation gate

**Status:** Bot DEPLOYED and running (read-only). The adapter authorization route is verified. The **agent URI has been updated** (2026-10-12, owner-authorized) through the adapter's controller route to a DEVin-branded registration — see "Agent URI update" below. Wallet binding is still deliberately unset (zero). No wallet transfer or ownership change has been made.

## Evidence (Base chain ID 8453, queried 2026-10-11)

- Loopers ERC-721 `0x1649cd37f4748807b4882fc48765ba0b2affa94a`: `ownerOf(706)` returned `0x23129c0472172D75bEd1e6dd061301796760Ecd9`.
- That collection's `erc8004AgentIdByLooper(706)` returned `87226`.
- A local nonce challenge signed with the configured agent wallet recovered the same `0x23129c0472172D75bEd1e6dd061301796760Ecd9` address. No key or signature was saved or published. This proves only that this environment can sign as the NFT owner at the time of the check.
- Base ERC-8004 IdentityRegistry `0x8004A169FB4a3325136EB29fA0ceB6D2e539a432`: `ownerOf(87226)` returned **`0x270d25D2c59A8bcA1B0f40ad95fF7806c0025c27`**, which differs from the Looper NFT owner. `getAgentWallet(87226)` returned the zero address. `isAuthorizedOrOwner(0x23129c0472172D75bEd1e6dd061301796760Ecd9,87226)` returned **false**. `tokenURI(87226)` points to a generic Looper #706 registration at `https://arweave.net/wC0L6LR_IGsS_SgAQFrSbnzsjVgAbOlwZcV_lbrp_v8/706.json`.

## Authorization route (verified read-only)

The registration is **owned by an adapter contract**, not an unrelated EOA. BaseScan's verified `Adapter8004` implementation is `0x0f81bd4EDD4879734361A1A44460264CBf6F94c9`, reached through proxy `0x270d25D2c59A8bcA1B0f40ad95fF7806c0025c27` (EIP-1967 implementation slot queried on-chain). Its `bindingOf(87226)` returned `(ERC721, 0x1649CD37f4748807b4882FC48765bA0B2aFfa94a, 706)` and `isController(87226, 0x23129c0472172D75bEd1e6dd061301796760Ecd9)` returned **true**. The verified source checks current bound-token ownership in `_requireController`, then forwards `setAgentURI`, `setAgentWallet`, or `unsetAgentWallet` to the ERC-8004 registry. A read-only `eth_call` simulation of `setAgentURI(87226, currentURI)` from the Looper-owner wallet succeeded (`0x`); the same simulation from an unrelated address reverted with `NotController`. Neither call submitted a transaction.

**Correction to the original gate:** direct `isAuthorizedOrOwner(LooperOwner, agentId)` is false because registry ownership stays with the adapter. This is expected under the adapter binding and does **not** block controller-mediated writes. The authorized route is via the adapter; do not call the registry directly or transfer the registry NFT. Control must be re-checked immediately before any write because transferring Looper #706 changes its controller. Wallet binding requires the registry's own wallet-proof signature and cannot be assumed from control alone.

## Remaining activation gates (on-chain only)

- **DONE (2026-10-12):** a DEVin registration file was prepared, schema-validated, published at an immutable public URL, preflighted with `eth_call`, written via `Adapter8004.setAgentURI`, and verified on-chain. See the next section.
- Decide whether an agent payment wallet is needed. If not, leave `getAgentWallet(87226)` unset (zero); do not bind the main Looper-owner wallet simply to make the field nonzero. If needed later, separate the spending wallet and explicitly approve the signature/domain/deadline and caps.

## Agent URI update (completed 2026-10-12, owner-authorized)

- **New URI:** `https://raw.githubusercontent.com/D0xedDevi0/d0xed-architect/31113662826f41ca2ededafeb469cc7e290831cf/devin/registration/agent-87226.json` (immutable, commit-SHA-pinned; source `devin/registration/agent-87226.json`).
- **Previous URI (for restore):** `https://arweave.net/wC0L6LR_IGsS_SgAQFrSbnzsjVgAbOlwZcV_lbrp_v8/706.json`
- **Tx:** `0x182bbb77f5b265cb03a881635e9f230af236b836785809fec1ae45474d61bce3` (status 0x1, gasUsed 133 681, signer `0x23129c0472172D75bEd1e6dd061301796760Ecd9` = Looper #706 owner).
- **Call:** `Adapter8004.setAgentURI(87226, newURI)` — controller route. Emitted `AgentURISet(87226, newURI, 0x23129c04…)` from the adapter and `URIUpdated(87226, newURI, adapter)` + `MetadataUpdate(87226)` from the registry.
- **Verified:** `IdentityRegistry.tokenURI(87226)` read back the new URI on two independent RPCs (mainnet.base.org, base-rpc.publicnode.com); the raw URL returns HTTP 200. The registration preserves every original field (trait atoms, class scores, personality, lore, activation, provenance) and adds DEVin's name/description/image, operator, Telegram handle, capabilities, and constraints.
- **Restore (one call):** `cast send 0x270d25D2c59A8bcA1B0f40ad95fF7806c0025c27 "setAgentURI(uint256,string)" 87226 "<previous URI>" --private-key <agent-wallet.key> --rpc-url https://mainnet.base.org`.
- **Durability caveat:** the pointer now depends on the `d0xed-architect` repo staying **public** (pin to the SHA above is immutable, but a deleted/private repo would 404 the metadata). If you'd rather host it on an owned domain (`d0xeddev.com`) or content-addressed storage, say so and it can be re-pointed in one call.

## Deployment (completed 2026-10-11)

The read-only, bounded Telegram bot lives in `devin/` (repo `feat/sentinel-v0.5`) and runs on the Hostinger VPS exactly like the other Looper companions (`looper-glass`, `looper-mrbates`):

- systemd unit `looper-devin.service`, dedicated unprivileged user `looper-devin`, tree `/srv/looper-agents/devin/`, stdlib-only venv, hardened unit (`ProtectSystem=strict`, `NoNewPrivileges`, empty `CapabilityBoundingSet`, `MemoryMax=384M`).
- Token supplied as an **encrypted systemd credential** (`/etc/credstore.encrypted/looper-devin.token`, mode `0600`), decrypted only into the service's `$CREDENTIALS_DIRECTORY`; never in `Environment=`, never on disk in cleartext, never in Git.
- Audience: owner DM `7898354400` and the shared Loopers group `-1004351143165` (fail-closed; everything else denied/silent). In a group the bot answers only when addressed (`/cmd@DEVinlooperbot` or a reply).
- Startup pins the bot identity via `getMe` (`DEVIN_BOT_ID=8803435794`) and refuses to run if a webhook is set.

**Verified**: 71 unit tests pass (mocked HTTP, no credentials, no network) plus a guard test proving no `subprocess`/`eval`/`exec`/wallet/payment imports; the service is `active` with no restarts and holds a live long-poll connection to Telegram; and a real audit run as `looper-devin` against live GitHub (`pallets/flask`: 102 files, 33 findings with `path:line` receipts) completed over the SSRF-pinned transport.

**Two owner actions still needed for the group/DM routes to be reachable** (Telegram-side, cannot be done for the owner):

1. Add `@DEVinlooperbot` to `@looper_collective`. Until then Telegram reports `chat not found` to the bot, which is expected.
2. Open a private chat with `@DEVinlooperbot` and send `/start`. Telegram does not deliver a bot's DM until the user initiates it.

## Out of scope / non-goals

The bot performs no spend, no wallet access, no on-chain writes, no LLM prompt execution, and never executes audited repository code. The credential supplied in chat was used at the owner's explicit direction; it passed through the chat transcript, so a BotFather revoke + vault re-entry is the remedy if that bot is ever compromised.


References: [adapter proxy](https://basescan.org/address/0x270d25D2c59A8bcA1B0f40ad95fF7806c0025c27#code), [verified adapter implementation](https://basescan.org/address/0x0f81bd4edd4879734361a1a44460264cbf6f94c9#code), [ERC-8004 registration](https://erc-8004.quicknode.com/agents/base-mainnet/87226).
