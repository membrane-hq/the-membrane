# Working with The Membrane

The Membrane is a self-hosted Rust authorization gate. This file helps agents
inspect and evaluate the repository. It is not a grant to deploy the gate,
change an operator's policy, obtain credentials, or perform upstream writes.

## Start with evidence

- [Security policy](SECURITY.md): early-stage software, no supported stable
  release or production-assurance guarantee.
- [Gate threat model](docs/threat-model-gate.md): trust boundaries, required-path
  assumptions and deployment responsibilities.
- [Local evaluation](docs/agent-evaluation.md): an automated signed allow/deny
  check with temporary keys and a canned model reply.
- [Caller identity](docs/caller-identity.md): caller-bound signed scopes and
  fresh request proofs, not bearer-scope authentication.
- [Policy as code](docs/policy-as-code.md): accepted policy generations,
  bootstrap with `registry migrate`, and updates with `registry apply`.
- [Pilot guide](docs/pilot.md): deployment requirements and evaluation scope.

## Build and evaluate

From the repository root, with stable Rust, a C toolchain, git, Bash, curl, jq
and Python 3 installed:

```bash
cargo build --locked -p membrane-cli --bin membrane --example operator-request
bash scripts/evaluate-local.sh
```

The evaluator builds from source, runs a loopback-only gate with a mock model,
checks HTTP 200 for a signed in-scope request and HTTP 403 for replay and missing
caller proof, and cleans up its temporary keys and process. It does not test
real model behavior, upstream writes, relay evidence export or production
readiness. Read the script before running it.

## Change checks

These match the Rust checks in `.github/workflows/ci.yml`:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --locked
cargo test --workspace --all-features --locked
```

The workflow also checks feature combinations, registries, release/deployment
fixtures, containers and the required-path deployment. Run relevant checks
when those parts change. See [CONTRIBUTING.md](CONTRIBUTING.md) for review,
licensing and DCO sign-off.

## Boundaries to preserve

- Only calls routed through the gate are governed. Production integration must
  make it the required path and protect operator and upstream credentials.
- Do not add production keys or tokens to demos, fixtures, issues or commits.
- Demo tool effects are simulated. A receipt records authorized request intent,
  not proof of a completed upstream write.
- Do not treat a model's recommendation or a successful local test as operator
  approval. Policy, credentials and real effects remain operator decisions.
- Read [enforcement limits](docs/audit-fixes.md) together with the superseding
  [durable-journal notes](docs/durable-journal.md) before making security claims.
