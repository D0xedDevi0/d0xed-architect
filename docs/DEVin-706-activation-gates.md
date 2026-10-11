# DEVin / Looper #706 — read-only activation gate

**Status:** BLOCKED; no Telegram bot, registry transaction, wallet transfer, signing request, or production process was started. Read-only Base queries and one local challenge signature only.

## Evidence (Base chain ID 8453, queried 2026-10-11)

- Loopers ERC-721 `0x1649cd37f4748807b4882fc48765ba0b2affa94a`: `ownerOf(706)` returned `0x23129c0472172D75bEd1e6dd061301796760Ecd9`.
- That collection's `erc8004AgentIdByLooper(706)` returned `87226`.
- A local nonce challenge signed with the configured agent wallet recovered the same `0x23129c0472172D75bEd1e6dd061301796760Ecd9` address. No key or signature was saved or published. This proves only that this environment can sign as the NFT owner at the time of the check.
- Base ERC-8004 IdentityRegistry `0x8004A169FB4a3325136EB29fA0ceB6D2e539a432`: `ownerOf(87226)` returned **`0x270d25D2c59A8bcA1B0f40ad95fF7806c0025c27`**, which differs from the Looper NFT owner. `getAgentWallet(87226)` returned the zero address. `isAuthorizedOrOwner(0x23129c0472172D75bEd1e6dd061301796760Ecd9,87226)` returned **false**. `tokenURI(87226)` points to a generic Looper #706 registration at `https://arweave.net/wC0L6LR_IGsS_SgAQFrSbnzsjVgAbOlwZcV_lbrp_v8/706.json`.

## Gate and handoff

The NFT ownership and local signer checks pass, but **registry owner/authorization and agent wallet binding do not**. The collection mapping alone does not confer rights to update the ERC-8004 registration. Do not claim DEVin is registered, wallet-bound, or authorized on behalf of registry agent 87226. Do not attempt `setAgentURI`, `setAgentWallet`, wallet connection, or a registry transaction from the NFT-owner key without a verified authorization route from the registry owner.

Before implementation/activation: establish who controls `0x270d25D2c59A8bcA1B0f40ad95fF7806c0025c27` and the sanctioned way to delegate/update the registration; re-query ownership and permissions; choose and explicitly authorize a separate Telegram bot/account and audience; define untrusted link/repository fetch policy, read-only sandbox and secret-redaction boundaries, spending caps, and tests for file:line + snippet/hash findings. The builder must distinguish static inspection from executed tests and never execute submitted code or act on page instructions by default. Packaging the crawler is not itself authorization to deploy a DEVin agent.
