# EVM enforcement: smart accounts as an authorization destination

Status: design direction. Nothing in this note is implemented. The gate today authorizes model and tool calls and meters inference spend through the Routstr rail ([settlement adapters](settlement-adapters.md)). No EVM account integration, session-key issuance, or onchain policy data exists in this repository. The Crossmint adapter (`membrane-gate::crossmint`) is the closest chain-adjacent code: it moves USDC through Crossmint's API, is mock-tested only, ships no signer, and enforces nothing onchain.

This note records an integration design for later build. It does not commit to an implementation schedule.

## The bypass problem

The gate is fail-closed where the agent's route to the backend is constrained to pass through it, as in the current proxy setup. Non-bypass is a property of the deployment, not of the proxy alone.

A chain transaction does not pass through any such route by default. If the key that controls the assets sits with the agent - an externally owned account (EOA) key, or a key that can be extracted - the holder can sign and submit transactions the gate never sees. Unrestricted signing authority bypasses an offchain check; what happens to such a transaction then depends on the controls of the account and the deployment.

Two ways to make authorization enforceable:

- Hold the assets in a smart account whose validation and execution rules require the authorization.
- Keep the key in custody that checks the operator's authorization before signing. A custody arrangement (MPC, TEE, or KMS) only helps if the custody itself enforces the policy; the label alone does not prevent bypass.

## Division of labor

- **The gate (offchain)** decides authorization from the operator's delegation and the request context, issues short-lived signed scopes, and records receipts.
- **The smart account (onchain)** enforces concrete limits: allowed target contracts, function selectors and argument constraints, native value and token spend caps, expiry, and replay protection.
- **Evidence** links the authorization and the policy that issued it to the resulting transaction hash.

Existing account-abstraction infrastructure provides the onchain half: ERC-4337 account validation, ERC-7579 modular accounts with session-key modules such as Smart Sessions, and ERC-7715 permission requests. The design builds on that infrastructure rather than reimplementing it. The gate's contribution is the connection between the two halves: the operator's delegation and request context on one side, the enforced limits and resulting transaction on the other, with receipts linking them.

## What an EVM scope would bind

The current credential (`IntentAuthorizationCredential` in `membrane-core/src/iac.rs`) binds a scope id, the caller's key, permitted channels, model and tool allowlists, forbidden exports, a validity window, and a context Merkle root. An EVM scope would additionally bind:

- `chainId`, against cross-chain replay.
- A nonce or nonce space.
- Allowed target contracts, function selectors, and argument constraints.
- Native value cap, token allowances, and fee caps.
- A deadline.

Outstanding ERC-20 approvals deserve separate treatment: an approved spender can pull tokens within its allowance without a new signature, so outstanding allowances sit outside any per-transaction session check. A deployment must inventory and constrain them.

## Issuing authority to an account

The gate signs credentials with BIP-340 Schnorr over secp256k1 (nostr), while account verification on EVM chains is built around ECDSA. The simpler path avoids translating the signature scheme: the owner authorizes a bounded permission, and a session key is registered with the account's session-key module together with those bounds. The gate's role is the authorization decision and the record of the owner's delegation; the session key is only ever valid within the permissions the owner granted. Verifying the gate's Schnorr signatures onchain instead is possible with published Solidity constructions ([noot/schnorr-verify](https://github.com/noot/schnorr-verify)) at higher cost, but this design does not require it.

Validation under ERC-4337 has no synchronous access to the gate or other network services. That does not mean policy data must be posted onchain ahead of time: signed data or proofs can accompany the request and be checked during validation, subject to the entry point's validation rules (ERC-7562).

## Where enforcement must sit

Validation alone is not enough. Account validation can check that an authorization exists, but cumulative limits (a budget across many transactions) and constraints that depend on runtime state must be enforced during execution, by the account or the modules it calls. When enforcement sits at the execution boundary, the check and the effect happen in the same state transition, with no check-then-act window.

Validation sees the transaction, not the reasoning behind it. A context hash can be committed onchain if a deployment wants the binding there; wherever it is stored, the hash binds the authorization to a context. It does not establish that the action was sensible or that the model understood the conversation. Simulation (`eth_call`) is advisory: state changes between simulation and inclusion, and contracts can detect simulation context. Limits that matter must hold at execution time, not preview time.

The spend ledger's reserve, finalize, and hold-uncertain discipline (`membrane-gate::spend`) already models pending-transaction semantics: a payment whose outcome is unknown stays held for operator reconciliation, because a timeout is not proof that nothing was paid. That discipline transfers directly to transaction submission and confirmation.

## Dependency inside the current build

Receipts currently bind the hash of the authorizing credential; they do not yet bind the registry revision whose policy produced the decision (`membrane-core/src/siem.rs` maps `policy_hash` from the IAC hash). An integration that links a transaction to the policy that permitted it depends on closing that gap first.

## References

- [ERC-4337: Account Abstraction Using Alt Mempool](https://eips.ethereum.org/EIPS/eip-4337)
- [ERC-7562: Account Abstraction Validation Scope Rules](https://eips.ethereum.org/EIPS/eip-7562)
- [ERC-7715: Grant Permissions from Wallets](https://eips.ethereum.org/EIPS/eip-7715)
- [Smart Sessions: ERC-7579 session-key module](https://github.com/erc7579/smartsessions)
- [Solidity BIP-340 verification](https://github.com/noot/schnorr-verify)
- [Settlement adapters design note](settlement-adapters.md)
