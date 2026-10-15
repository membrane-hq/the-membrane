# Contributing to the Membrane

The Membrane is early-stage, single-maintainer software. Bug reports, tests, documentation fixes and focused code changes are welcome.

## Before you start

- For anything larger than a small fix, open an issue first so we can agree on scope before you write code.
- Security problems: do not open a public issue. Follow [SECURITY.md](SECURITY.md) and email membrane@dojopop.live.
- Questions and bug reports go in [GitHub issues](https://github.com/membrane-hq/the-membrane/issues). Please include the commit you ran, what you expected, what happened, and a minimal reproduction.

## Making a change

1. Fork the repository and create a branch from `main`.
2. Keep the change small and focused. One concern per pull request.
3. Add or update tests for any new or changed behavior. A change that adds functionality without a test will be asked for one.
4. Run the same checks CI runs. They must pass cleanly, including clippy warnings:

   ```bash
   cargo fmt --all -- --check
   cargo clippy --workspace --all-targets --locked -- -D warnings
   cargo test --workspace --locked
   ```

   CI also runs the tests and clippy with `--all-features`, and builds the container images under `deploy/`.
5. Open a pull request against `main` and describe what changed and why. The maintainer reviews every pull request; there is no response-time promise.

## Coding expectations

- Rust stable, edition 2021, formatted with `rustfmt`.
- The gate fails closed. A change that makes a denial path more permissive needs an explicit explanation and a test showing the denial still holds.
- Keep public claims in docs accurate. Say what the code does today, not what is planned. Planned work belongs in clearly labeled roadmap text.
- No secrets, private keys or real credentials in code, tests or fixtures.

## Licensing of contributions

Contributions are accepted under the license of the files they change (inbound = outbound):

- Code is licensed under AGPL-3.0-only (see [LICENSE](LICENSE)).
- Documentation and research documents are licensed under CC BY 4.0 (see [LICENSE-CC-BY-4.0](LICENSE-CC-BY-4.0)).

There is no contributor license agreement. You keep the copyright in your contribution.

## Sign off your commits (DCO)

Every commit in a pull request must carry a `Signed-off-by` line, which certifies the [Developer Certificate of Origin 1.1](https://developercertificate.org/): that you wrote the change or have the right to submit it under the license of the files you changed. Add it with `git commit -s`:

```
Signed-off-by: Your Name <you@example.com>
```

Use your real name and an email address you control. If you forgot, run `git commit --amend -s` for the last commit, or `git rebase --signoff main` for several, then force-push your branch.
