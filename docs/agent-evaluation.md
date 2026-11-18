# Evaluate The Membrane locally

The Membrane is a self-hosted authorization gate for requests routed through it.
This check lets a person or coding agent test caller authentication before
considering an integration. It is not an installation on production systems.

## Prerequisites

Use a disposable local environment with stable Rust and Cargo, a C toolchain,
git, Bash, curl, jq and Python 3. Dependency download needs network access.
The check needs no Docker, paid API, existing signing key or production token.

From the repository root:

```bash
bash scripts/evaluate-local.sh
```

The script builds the shipped CLI and `operator-request` helper. It creates a
private temporary directory, generates separate test operator/caller keys,
records the generated registry's initial accepted policy generation, and issues
a 15-minute caller-bound scope. It starts the production gate route on an
available loopback port with `MEMBRANE_DEV_MOCK_MODEL=1`.

Expected output includes:

```text
PASS: signed, in-scope request (200)
PASS: identical caller proof replay refused (403)
PASS: missing caller proof refused (403)
```

The allowed response must also include a receipt-hash header and a nonempty
model-choice array. Each denied response is checked for the expected reason,
not only its status code. Failures exit nonzero. The script stops the gate and
removes its temporary files, including private test keys, on exit.

The local runtime subprocesses get a fresh environment rather than inherited operator
credentials or telemetry configuration. The relay target is loopback port 9;
no relay is required for these assertions. Connection retries can add tens of
seconds. The model reply is canned; this is not a real-model or relay test.

## What a pass does and does not establish

A pass exercises caller authentication and refusal of replayed or missing
proofs through `/v1/chat/completions`. It does not establish enforcement for
all policies or tools, revocation, durable relay history, a real upstream write,
production deployment, independent audit, or a service's willingness to accept
an agent. A receipt attests authorized request intent, not upstream completion.

The hosted demo is separate: a recorded replay followed by simulated operator
traffic, with no gate behind the public page. The local interactive demo also
simulates tool effects. Neither is a production security test.

## Before integration

- Read [SECURITY.md](../SECURITY.md), [caller identity](caller-identity.md),
  [policy as code](policy-as-code.md), [gate threat model](threat-model-gate.md),
  [enforcement limits](audit-fixes.md)
  and [durable journal](durable-journal.md).
- Run the [operator walkthrough](operator-walkthrough.md) for a local relay,
  published receipts and evidence export. Use a separate check with a real
  model backend before making claims about a real-model integration.
- Have the operator choose the workflow, grant, supported connector and secret
  handling. Make the gate the required network path. Direct upstream access
  and compromised caller keys are outside this check's protection.
- Follow the [pilot guide](pilot.md). The software is early-stage, with no
  supported stable release, production-assurance guarantee or support SLA.
