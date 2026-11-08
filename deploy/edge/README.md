# Required-path reference deployment

The gate and its model backend sit on an internal network with no published
ports; the only route to them is through the edge proxy, and the gate
refuses any production request without a valid assertion from the pinned
edge issuer. The proxy here is a stand-in: it does not authenticate callers
or mint assertions, and the checked-in test key is public. See
[docs/edge-deployment.md](../../docs/edge-deployment.md)
for the model, the production composition and what this deliberately does
not build (no login, MFA or attack filtering).

Run the check:

```bash
cargo build --locked -p membrane-cli --bin membrane --example operator-request
docker build -f deploy/gate/Dockerfile -t membrane-gate:local .
deploy/edge/verify.sh
```

`verify.sh` generates throwaway operator and caller keys into `./config`
(gitignored), starts the stack, checks that direct connections fail and both
checks are enforced, runs an authorized call end to end, and tears down.
