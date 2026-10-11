# Security policy

The Membrane is early-stage software. The current main branch receives security
fixes; there is no supported stable release or production-assurance guarantee.
Operators should review the documented enforcement and deployment limits before
using the gate with production credentials or write access.

## Report a vulnerability

Email membrane@dojopop.live with a private report. Include the affected commit,
component, expected behavior, observed behavior and a minimal reproduction if
possible. Do not include passwords, tokens, private signing keys or customer data.
Do not post an exploit or sensitive details in a public issue.

GitHub private vulnerability reporting is not enabled for this repository. Use
the email route above. Public issues remain appropriate for non-sensitive bugs.

The research specification describes a 90-day coordinated disclosure process.
Please coordinate disclosure privately with the maintainer. This policy does not
promise a response time, fix deadline, audit certification or bug bounty.

## Scope and deployment limits

Caller proof, signed IACs and registry grants apply to requests routed through the
gate. They do not constrain direct access to an upstream system or protect a
compromised caller key. The demo simulates effects and is not a production
security test. BCI, zk-STARK and TEE components in the research specification are
not implemented in this repository.

See [enforcement limits](docs/audit-fixes.md),
[caller identity](docs/caller-identity.md) and
[durable journal](docs/durable-journal.md) for current assumptions and limits.
