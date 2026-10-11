# DEVin / Looper #706 — read-only activation gate

**Status:** Contract authorization route identified; activation remains pending a reviewed agent URI, wallet-binding decision, rotated bot credential, audience policy, and deployment choice. No Telegram bot, registry transaction, wallet transfer, or production process was started. Read-only Base queries and one local challenge signature only.

## Evidence (Base chain ID 8453, queried 2026-10-11)

- Loopers ERC-721 `0x1649cd37f4748807b4882fc48765ba0b2affa94a`: `ownerOf(706)` returned `0x23129c0472172D75bEd1e6dd061301796760Ecd9`.
- That collection's `erc8004AgentIdByLooper(706)` returned `87226`.
- A local nonce challenge signed with the configured agent wallet recovered the same `0x23129c0472172D75bEd1e6dd061301796760Ecd9` address. No key or signature was saved or published. This proves only that this environment can sign as the NFT owner at the time of the check.
- Base ERC-8004 IdentityRegistry `0x8004A169FB4a3325136EB29fA0ceB6D2e539a432`: `ownerOf(87226)` returned **`0x270d25D2c59A8bcA1B0f40ad95fF7806c0025c27`**, which differs from the Looper NFT owner. `getAgentWallet(87226)` returned the zero address. `isAuthorizedOrOwner(0x23129c0472172D75bEd1e6dd061301796760Ecd9,87226)` returned **false**. `tokenURI(87226)` points to a generic Looper #706 registration at `https://arweave.net/wC0L6LR_IGsS_SgAQFrSbnzsjVgAbOlwZcV_lbrp_v8/706.json`.

## Authorization route (verified read-only)

The registration is **owned by an adapter contract**, not an unrelated EOA. BaseScan's verified `Adapter8004` implementation is `0x0f81bd4EDD4879734361A1A44460264CBf6F94c9`, reached through proxy `0x270d25D2c59A8bcA1B0f40ad95fF7806c0025c27` (EIP-1967 implementation slot queried on-chain). Its `bindingOf(87226)` returned `(ERC721, 0x1649CD37f4748807b4882FC48765bA0B2aFfa94a, 706)` and `isController(87226, 0x23129c0472172D75bEd1e6dd061301796760Ecd9)` returned **true**. The verified source checks current bound-token ownership in `_requireController`, then forwards `setAgentURI`, `setAgentWallet`, or `unsetAgentWallet` to the ERC-8004 registry. A read-only `eth_call` simulation of `setAgentURI(87226, currentURI)` from the Looper-owner wallet succeeded (`0x`); the same simulation from an unrelated address reverted with `NotController`. Neither call submitted a transaction.

**Correction to the original gate:** direct `isAuthorizedOrOwner(LooperOwner, agentId)` is false because registry ownership stays with the adapter. This is expected under the adapter binding and does **not** block controller-mediated writes. The authorized route is via the adapter; do not call the registry directly or transfer the registry NFT. Control must be re-checked immediately before any write because transferring Looper #706 changes its controller. Wallet binding requires the registry's own wallet-proof signature and cannot be assumed from control alone.

## Remaining activation gates

- Prepare an agent registration file describing only the DEVin capabilities and reachable endpoints that actually exist, then validate the schema and publication destination before calling `Adapter8004.setAgentURI`; use `eth_call` preflight and verify the on-chain URI afterward. No registration update has been made.
- Decide whether an agent payment wallet is needed. If not, leave `getAgentWallet(87226)` unset (zero); do not bind the main Looper-owner wallet simply to make the field nonzero. If needed later, separate the spending wallet and explicitly approve the signature/domain/deadline and caps.
- The bot credential supplied in chat is exposed in transcript history. Revoke it through BotFather and deliver the replacement through a masked vault entry, **not another chat message**. Do not embed it in Git, docs, logs, commands, or test fixtures.
- Define Telegram DM/group audience and an actual deployment target. This hosted Hermes container cannot host an additional persistent bot process or expose arbitrary inbound ports. No external deployment is authorized by this document.
- Implement read-only, bounded, allowlisted repository/URL inspection with prompt-injection containment, SSRF controls, resource caps, static-versus-executed evidence labels, and file:line/snippet/hash findings. Never run submitted code by default or grant the crawler access to local secrets.

References: [adapter proxy](https://basescan.org/address/0x270d25D2c59A8bcA1B0f40ad95fF7806c0025c27#code), [verified adapter implementation](https://basescan.org/address/0x0f81bd4edd4879734361a1a44460264cbf6f94c9#code), [ERC-8004 registration](https://erc-8004.quicknode.com/agents/base-mainnet/87226).
