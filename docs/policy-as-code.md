# Channel registry as code

The channel registry is the gate's policy: which
callers hold grants, which
models, channels, tools and repositories are allowed, whether out-of-scope
tool calls are held for approval, and which identities may spend against a
budget. The gate reads it from a YAML file and re-reads that file on every
identity authorization check.

Because the policy is one file, it can live in version control and change
through the same review loop as code. Four CLI commands close that loop:
`validate` in CI, `diff` in review, `apply` on deploy; `migrate` once per
registry to record the first accepted generation, and again only for a
deliberate trust reset.

## Validate

```bash
membrane registry validate registry.yaml
membrane registry validate registry.yaml --strict   # warnings become errors
membrane registry validate registry.yaml --json     # machine-readable report
```

Validation catches the conditions that make a policy unusable or misleading
before the gate ever sees them:

- structural errors: unparseable YAML and unknown top-level keys. A typo in a
  required key (`permitted_channels`, `forbidden_exports`, `model_allowlist`)
  fails to parse at all. A typo in an optional key (`identities`,
  `github_repo_allowlist`, `approval`, `delta_t_secs`, `model_api_url`) is
  worse: the runtime parser ignores unknown keys, so the setting silently
  falls back to its default - no approval holds, an empty allowlist, a 300
  second delta_t, or no model backend
- window errors: `valid_for` together with `expires_at`, `valid_for` without
  `not_before`, an unparseable `valid_for`, `expires_at` not after
  `not_before` - each denies every request from that identity
- dead allowlist entries: a grant naming a model or repository the registry
  does not allow can never authorize anything
- malformed entries: identity keys that are not 64-character lowercase hex,
  repositories that are not `owner/name` slugs, zero `delta_t_secs`
- spend errors: empty budget names, zero caps, a per-call ceiling above the
  budget cap, and two grants that name the same budget with different caps
  (the second grant's spend call is denied as a budget conflict)

Warnings mark legal configurations to confirm as deliberate, such as an empty
`identities` map (denies every production caller) or an expired grant.
`--strict` turns warnings into a non-zero exit.

Run it in CI so a broken policy cannot merge:

```yaml
- run: cargo run --locked -q -p membrane-cli -- registry validate registry.yaml
```

(The workflow in this repository validates both checked-in registries this
way.)

## Review a change

```bash
membrane registry diff registry.yaml registry-candidate.yaml
membrane registry diff registry.yaml registry-candidate.yaml --json
```

The diff lists added, removed and changed identities, field-level grant
changes (scopes, allowlists, windows, spend) and top-level changes
(allowlists, `delta_t_secs`, `model_api_url`, approval policy). Grant windows
render as UTC timestamps with the raw Unix value. It answers the review
question directly: what does this pull request change about who can do what.

## Apply

```bash
membrane registry apply registry-candidate.yaml --to /etc/membrane/registry.yaml
```

Apply validates the candidate first and refuses to install it when the report
contains errors; the live registry stays unchanged. A valid candidate is
written to a temporary file in the same directory, synced, and renamed over
the live file, so the gate never reads a partial policy. Because the gate
re-reads the registry file on every identity authorization check, the rename
is the whole deploy: no restart, no signal, no reload window.

Every apply is a new generation. The registry carries a `revision` number
and a candidate must advance it: earlier policy rules can return only as a
new, higher revision, never as the generation outstanding approvals are
bound to. Monotonicity is checked against the durably recorded generation,
not just the live file: restoring earlier bytes and re-applying them, with
or without a revision bump, cannot move the accepted generation backwards.
An install commits two files in order - the registry, then the generation
record (policy epoch, revision and sha256 of the exact installed bytes) in
`<registry>.revision-state.json`. Each write is atomic (temp file, sync,
rename). An interrupted install fails closed: for an existing recorded
generation, re-apply the candidate; an interrupted first install requires
explicit `migrate`. An install lock serializes concurrent applies and
migrates. The gate checks every live read against that record. Anything that
did not come through `apply` - a direct file edit, a rollback to earlier
bytes, an edit that bumps `revision` by hand, a half-finished install -
fails closed with a 403 until the operator installs a real update. An
approval granted under one generation can never come back to life under
another through any supported update, even if the policy rules that return
are identical to what was approved under.

This guarantee covers the enforced path: `membrane gate` loads its startup
policy from the same registered registry file the gate verifies, so every
policy input to an approval's digest passes the generation check. A deployment
that constructs the gate library with startup policy independent of the
registered file still gets change detection through the digest, but rollback
protection extends only to the registered file.

If a broken registry ever reaches the live path by another route, the gate
fails closed: authorization checks error until a valid file is installed
through `apply`. `apply` exists so that state is hard to reach.

The epoch is what makes reset safe. It is random, generated only by a first
install or an explicit `membrane registry migrate --to <registry>`, carried
forward unchanged by ordinary installs, and bound into every policy digest.
So a live registry with no recorded generation is never silently adopted:
`apply` refuses it, because recording one is a trust reset. Because migrate
always starts a fresh epoch, approvals granted before a reset never match
again - even if the reset restores identical policy rules at the original
revision - and no one has to locate and edit the approval store. Upgrading to the generation-checking gate therefore
takes one `migrate` per registry; until then the gate refuses calls rather
than guess. The same refusal covers an interrupted first install (live file
written, record never committed): the check cannot distinguish that crash
from a deleted record, so recovery always takes the explicit `migrate` path,
even when no earlier approvals exist to invalidate.

If the record is lost or corrupt: restore the correct current record if you
have it - a repair that invalidates nothing - or remove it deliberately and
re-run `membrane registry migrate`, a trust reset whose fresh epoch
invalidates every outstanding approval. Rolling the registry file and the
record back together, or forging the record, requires the same operator
storage access that could replace the approval store, and remains outside
the threat model.

## Schema for editors and other tools

`schemas/channel-registry.schema.json` describes the registry's shape for
editors and schema-aware tooling. It covers structure only; the semantic
checks above (dead allowlist entries, window contradictions, budget
agreement) are what `membrane registry validate` adds on top. The schema is
a file in this repository, referenced by path; it is not hosted anywhere.
