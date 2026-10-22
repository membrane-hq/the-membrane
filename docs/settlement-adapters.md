# Settlement adapters: spend as policy

Status: design direction. This note proposes a shared spend-policy boundary with Routstr and Crossmint adapters. It does not add payment support or commit an implementation schedule. Implementation status: the budget ledger (`membrane-gate::spend`), a Routstr adapter (`membrane-gate::routstr`) and an opt-in gate route (`POST /v1/spend/chat`) exist with mock-rail tests. They have not been run against a live Routstr node, and funding and refund calls are not built. A Crossmint adapter (`membrane-gate::crossmint`) exists with mock-rail tests and an HTTP client tested against a local stand-in server. It has not been run against Crossmint, no approval signer ships, and it is not wired to a gate route.

## Boundary

The Membrane checks caller-bound, signed, time-bounded authorization before model and tool calls execute. Spending should pass through the same boundary: permission to call a service is not permission to spend without a limit.

A proposed spend scope would bind the caller and task to a settlement rail, asset and unit, allowed service or payee, per-call ceiling, cumulative budget, and validity window. Budget accounting must be durable and atomic across concurrent calls. An adapter would translate an approved intent into the rail's payment flow; it would not grant authority or change policy.

## Two rails, one gate integration

- **Routstr: Bitcoin ecash inference.** Routstr offers OpenAI-compatible inference paid with Cashu ecash or Lightning. Its prepaid, ephemeral balance model exchanges a Cashu token for an `sk-...` key, meters requests, and returns unused balance as ecash. It reserves a ceiling before forwarding and finalizes against measured or auditable estimated token cost. This fits operator-controlled funding without a permanent user account. It still depends on the selected Routstr node, upstream inference provider, and Cashu mint; accountless access is not absence of counterparty risk.
- **Crossmint: stablecoin machine payments.** Crossmint Agent Wallets provide non-custodial smart wallets with delegated agent signers. Owners set spend caps, allowed counterparties, and time windows; wallet permissions are enforced onchain and revocable. Crossmint documents per-call x402 and MPP payment flows. Its regulated services use direct licensing and licensed partners, with coverage dependent on product, jurisdiction, and onboarding. Wallet delegation does not itself establish regulatory coverage for an application.

Both adapters would implement the same gate-side intent and evidence contract. They would retain rail-specific pricing, units, signing, finality, fees, and refund rules. No automatic conversion or fallback between assets or rails is implied.

## Proposed execution and evidence

1. Validate the live scope, destination, asset, and maximum total cost, including fees. Deny if a cost ceiling cannot be established or policy does not cover it.
2. Reserve the ceiling against the shared budget before dispatch. Keep funding tokens and signing credentials outside model-visible context; prevent agents from bypassing the gate with broader payment credentials.
3. Dispatch once through the selected adapter. Bind the payment intent to the authorized request with an idempotency identifier.
4. Record the rail's settlement result and final cost, then release any unused reservation. If dispatch may have spent funds but confirmation is missing, retain the reservation and reconcile before retrying. A timeout is not proof that nothing was paid.

Proposed receipt fields include the scope and request identifiers, rail, asset and unit, payee, reserved ceiling, final cost and fees, settlement reference, and outcome. Do not include bearer tokens, Cashu proofs, or signing keys. A Membrane authorization receipt and a provider's settlement record prove different things; link them without treating either as a substitute for the other.

## Operator setup (routstr, opt-in)

The route is off unless `MEMBRANE_SPEND_DIR`, `MEMBRANE_ROUTSTR_POLICY` and `MEMBRANE_ROUTSTR_API_KEY` are all set; a partial setup stops startup. The policy file (YAML) names the node, per-model prices in msat per million tokens, and a per-call ceiling. The funded `sk-` key is supplied by the operator and never read from a request. An identity may spend only with a `spend` grant in the identity registry (`budget`, `budget_cap_msat`, `per_call_ceiling_msat`), on top of the usual scope, channel and model checks. The request carries an `operation_id` and a chat body with `max_tokens`; budget, limits and rail come only from the grant. Reservation ids are bound to the authenticated caller and scope. Reservations that may have been charged stay held and appear as `spend_open` in the loopback operations report; they are never retried or resolved automatically.

## Crossmint adapter: what exists and what does not

Exists, mock-tested: `membrane-gate::crossmint`, using the same ledger discipline as Routstr. A payment intent is checked against an operator policy (allowlisted payee addresses, per-call ceiling in micro-USDC, chain and token), the amount is reserved in the shared budget, then one transfer is dispatched with the reservation id as the `x-idempotency-key`. A transfer that reaches `success` is finalized; a 4xx refusal or `failed` status releases the reservation; a timeout, 5xx, `pending` or `awaiting-approval` transfer stays held as uncertain for operator reconciliation. Receipts carry the Crossmint transaction id as the settlement reference and no keys or signatures. The API key is read from `MEMBRANE_CROSSMINT_API_KEY`, the policy from the YAML file named by `MEMBRANE_CROSSMINT_POLICY`; neither is read from a request, and a partial setup is an error. The policy sets `api_base` explicitly (there is no default environment).

What the adapter assumes, from Crossmint's wallet REST docs (2025-06-09 API version): a transfer is `POST /wallets/{wallet}/tokens/{chain}:{token}/transfers` with `recipient`, a decimal `amount` and a `signer` locator, returning a transaction with status `awaiting-approval`, `pending`, `success` or `failed`; an approval is `POST /wallets/{wallet}/transactions/{id}/approvals`; Crossmint covers gas. Transfers are final and not reversible once confirmed, so there is no refund path.

Does not exist: any live run, a signer implementation (the approval message must be signed by a key the operator controls; without a signer a transfer stays unapproved and held), a gate route for Crossmint spend, funding flows, and balance reconciliation. The x402 and MPP per-call flows are not implemented: Crossmint documents them through its TypeScript SDK and the x402 client libraries, which sign payments client-side. Whether the wallet's onchain agent-signer caps (spend limit, counterparties, time window) are configurable over REST was not verified; the gate's own budget and payee allowlist are the enforced limits here.

## Limits and open checks

This direction does not make the Membrane a wallet, mint, custodian, exchange, or compliance service. Before implementation, validate adapter APIs, concurrency and recovery behavior, wallet-policy compatibility, production protocol support, and fees. Crossmint's MPP example targets a devnet; production availability needs separate verification. Confirm product-specific regulatory responsibilities with the provider and qualified counsel. Neither rail removes obligations attached to a separate ecash mint.

## References

- [Routstr payment flow](https://docs.routstr.com/client/payments/) and [refund semantics](https://docs.routstr.com/api/endpoints/).
- [Crossmint Agent Wallets](https://docs.crossmint.com/agents/wallets/overview), [x402](https://docs.crossmint.com/agents/payment-flows/x402), and [MPP](https://docs.crossmint.com/agents/payment-flows/mpp).
- [Crossmint regulatory scope](https://docs.crossmint.com/stablecoin-orchestration/concepts/regulatory-landscape) and [service terms](https://www.crossmint.com/legal/crossmint-terms-of-service/TRGUSAALLALLALL).

## Live verification, 2026-10-22 (routstr rail)

Verified end to end with real ecash against node `https://routstr.eduvietkieu.com`
(Hana Gateway v0.4.7, mint `https://mint.minibits.cash/Bitcoin`), model
`claude-haiku-4-5`, through the gate's `POST /v1/spend/chat`:

- Funded by importing a 2,000-sat cashu token via `GET /v1/balance/create`,
  which issued an `sk-` key with a 2,000,000 msat balance.
- Settled call: reserved ceiling = final cost = 102 msat at operator policy
  prices; the node's own meter charged 13 msat.
- Same `operation_id` twice: second call refused (409), never dispatched.
- Tiny-budget identity: second call blocked (402) once the budget could not
  cover the ceiling.
- A hanging upstream (`deepseek-v4-flash` on this node, unresponsive >120s at
  test time) exercised the real failure path: the ceiling stayed held as
  `uncertain` for reconciliation and the operation stayed replay-safe. A
  timeout is not proof nothing was paid. Prefer a verified-responsive model;
  `claude-haiku-4-5` answered in ~3s.
- Remaining balance withdrawn via `POST /v1/balance/refund` as a cashu token;
  lifetime spend 84 msat.
