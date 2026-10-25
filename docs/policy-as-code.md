# Channel registry as code

The channel registry is the gate's policy: which
callers hold grants, which
models, channels, tools and repositories are allowed, whether out-of-scope
tool calls are held for approval, and which identities may spend against a
budget. The gate reads it from a YAML file and re-reads that file on every
identity authorization check.

Because the policy is one file, it can live in version control and change
through the same review loop as code. Three CLI commands close that loop:
`validate` in CI, `diff` in review, `apply` on deploy.

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

If a broken registry ever reaches the live path by another route, the gate
fails closed: authorization checks error until a valid file is restored.
`apply` exists so that state is hard to reach.

## Schema for editors and other tools

`schemas/channel-registry.schema.json` describes the registry's shape for
editors and schema-aware tooling. It covers structure only; the semantic
checks above (dead allowlist entries, window contradictions, budget
agreement) are what `membrane registry validate` adds on top. The schema is
a file in this repository, referenced by path; it is not hosted anywhere.
