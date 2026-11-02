# Self-hosted pilots

A pilot runs the Membrane gate in your own environment, in front of one real agent workflow. You hold the keys, set the policy, and evaluate the gate's decisions and evidence on your own systems.

The Membrane is early-stage software with a single maintainer, no stable release and no production-assurance guarantee; see [SECURITY.md](../SECURITY.md). A pilot is a structured evaluation of what the gate does today.

## What a pilot covers

- The gate in front of the models and tools your agents use: caller-bound signed scopes, operator-owned grants and revocation, and a tamper-evident receipt chain.
- The operator dashboard, including approval gates ([approval-gates.md](approval-gates.md)). A gate holds a `POST /v1/tools/invoke` call to an operator-configured holdable tool only when the caller is authenticated, the scope is valid, and the tool alone is outside the caller's grant; a call that fails any other check is blocked, not held. An approval authorizes exactly one call, bound to that caller, scope and request, and never widens the caller's standing grant. Approval gates require operator OIDC and a durable approval store.
- Evidence export: a hash-chained, tamper-evident receipt for every decision in the runs you evaluate.
- A deployment shape from the [reference stack](reference-stack.md): local models on your hardware, up to fully air-gapped operation. The reference stack is a reference design; only the llama.cpp model path has been exercised end to end, per its status note.

A receipt records the authorized intent behind a request; it is not proof of a completed upstream write. Current enforcement limits are in [audit-fixes.md](audit-fixes.md) and [SECURITY.md](../SECURITY.md).

## Prerequisites

- One agent workflow to govern, with the in-scope models, tools and production actions named.
- A Linux host. The quickstart and local demo need no Docker, relay or paid API. A containerized self-hosted deployment needs Docker, with hardware sized per the tiers in the [reference stack](reference-stack.md).
- An operator who holds the signing keys and owns grant and approval decisions.

## Evaluate first

1. Run the [quickstart](quickstart.md): from clone to a refused call in about five minutes.
2. Run the [operator walkthrough](operator-walkthrough.md) for the full local path: keys, grants, relay, receipts and evidence export.
3. Read the [product overview](product.md) and the [reference stack](reference-stack.md) for the deployment model, hardware tiers and air-gapped operation.

## Request a pilot

Open a [self-hosted pilot request](https://github.com/membrane-hq/the-membrane/issues/new?template=pilot-request.yml). The issue is public: describe the workflow, models and tools, desired timeline and self-hosting constraints at a high level. Do not include secrets, credentials, customer data, proprietary prompts or internal hostnames.

For details that should not be public, email membrane@themembrane.org. Never send passwords, tokens or private signing keys through either route.

The maintainer reviews each request and follows up on the issue or by email. There is no response-time commitment. Questions during an evaluation go through the same two routes; there is no support SLA. Security reports follow [SECURITY.md](../SECURITY.md).
