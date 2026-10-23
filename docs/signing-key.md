# Signing-key handling

Every signing CLI command accepts `--nsec-file PATH` or `NOSTR_NSEC_FILE`.
Use a private, untracked file containing the Nostr signing key (bech32 nsec or
hex); surrounding whitespace is trimmed. On Unix, group/other permissions
must be unset, for example `chmod 600 /run/secrets/nostr-nsec`.

```bash
export NOSTR_NSEC_FILE=/run/secrets/nostr-nsec
membrane gate start --registry /etc/membrane/registry.yaml --iac /etc/membrane/iac.json
```

Provision the file through the operator's own secret-management process. Do not
paste the key into a shell command, commit it, or give the operator key to an
agent. Caller commands need their own caller key, not the operator issuing key.
The local walkthrough helper generates separate owner-only `operator.nsec` and
`caller.nsec` files and accepts `NOSTR_NSEC_FILE` when signing requests.

## Source precedence

1. `--nsec-file`, otherwise `NOSTR_NSEC_FILE`.
2. Legacy `--nsec` raw value.
3. Legacy `NOSTR_NSEC` raw value.

A configured file wins even over a raw flag. An unreadable, empty, invalid, or
insecurely permissioned file fails the command; it never falls back to a raw
value. An empty file path is also an error. Raw flag and environment inputs
remain supported for compatibility, but the file source is preferred.

## What this protects

Key text read by the loader is held in the existing redacted, zeroed-on-drop
`Secret` type. CLI help does not read or display the raw environment value.
Invalid-key errors do not echo the input. The loaded key is passed to the Nostr
library for local signing; this is not remote signing or external-vault delivery.

Limits: a file does not protect against an attacker who can read the operator's
files or process memory. The environment fallback still leaves a copy in the
process environment and potentially `/proc/<pid>/environ`; raw flags can appear
in process listings and shell history. Argument parsing and the Nostr library
can make their own copies. Zeroing the loader's text is not a guarantee that all
key material in the process is erased. Unix permission checks do not validate
Windows ACLs, file ownership, symlink targets, or concurrent file replacement.
Deployments using the old environment source are not migrated automatically.
