# Security policy

The Membrane is early-stage software. The current main branch receives security fixes; there is no supported stable release or production-assurance guarantee. Review the gate threat model (docs/threat-model-gate.md) and the documented limits before using the gate with production credentials or write access.

## Report a vulnerability

Report privately through GitHub private vulnerability reporting on this repository (Security > Advisories > Report a vulnerability: https://github.com/membrane-hq/the-membrane/security/advisories/new), or email membrane@themembrane.org. Include the affected commit, component, expected and observed behavior, impact, and a minimal reproduction if possible. Do not include real passwords, tokens, private signing keys or customer data. Do not post an exploit or sensitive details in a public issue.

## What to expect

This is a one-maintainer project. We will try to acknowledge your report within 7 days. Acknowledgment is not a decision; we will tell you our assessment after we have looked at it, and we do not promise a time for that or for a fix. We will keep you updated on accepted reports, credit you if you wish, and publish a GitHub security advisory when a fix is released. There is no bug bounty.

## Disclosure

We ask you to coordinate public disclosure with us and to allow up to 90 days for a fix. This is a request, not a legal condition. If you think the timeline is wrong, for example the issue is already public or being exploited, tell us the date you intend to publish and we will work with you.

## Scope

In scope: the code in this repository on main, including the gate, CLI, connectors, journal, dashboard and caller and operator authentication. Examples: bypassing caller proof, IAC or registry grants, replay protection, approval gates, severance, the journal or receipts; exposing key material or connector tokens through the software (logs, errors, files, command lines, permission checks); and denial of service that exceeds a documented limit, including by an authorized caller.

Known limits, not vulnerabilities by themselves: the gate does not constrain direct access to an upstream system, and it cannot protect a caller or operator key that is compromised by means outside the software. If you can show the software makes either easier than documented, report it.

Outside this policy: the simulated demo, research components in the whitepaper (BCI, zk-STARK, TEE), settlement adapters that are mock-tested only, and third-party services (report those to the vendor). Automated scanner output is welcome if it comes with evidence of impact; we may ask for it.

## Testing

Test against your own instance with your own keys. Do not test against systems or accounts you do not own, access other people's data, or degrade a service you do not run. Stop and report once you confirm an issue.

## Good-faith research

If you follow this policy in good faith, the maintainers will not start legal action against you for that research. This covers only the maintainers and Dojopop Nishi LLC, not GitHub, hosting providers or other third parties.

## Merkle commitment guarantees

Two Merkle constructions are in scope (docs/whitepaper.md section 5.1):

- The **set commitment tree** (5.1.1) commits to the set of leaves only. By design it does not commit to exact leaf count or order, and a set root must never be presented as evidence of an exact event count or sequence.
- The **ordered log tree** (5.1.2) commits to an append-only sequence with inclusion and consistency proofs. Any claim involving count, order or third-party verification must use this tree.

Byte-level details: [docs/merkle-trees.md](docs/merkle-trees.md).

See [enforcement limits](docs/audit-fixes.md), [caller identity](docs/caller-identity.md) and [durable journal](docs/durable-journal.md) for current assumptions and limits.
