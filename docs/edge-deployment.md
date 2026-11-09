# Edge assertions and the required-path deployment

The gate can require every production request to carry proof that its
holder authenticated at an edge the operator trusts, and the reference
deployment in `deploy/edge/` puts the gate and its model backend where only
that edge can reach them. Two independent checks then hold: permission to
reach the gate through the edge, then the existing permission to perform
the specific action.

This page is about composing the gate with an edge identity layer you already
run. The gate does not become one: no human login, no MFA enrollment, no bot
or flood filtering, no origin hiding is implemented here. Those belong to the
edge (for example Cloudflare Access in front of a tunnel) and to the network.

## Why

Caller-bound IACs and per-request proofs decide whether an authenticated
caller may perform an action. They do not decide how a request reached the
gate. If the gate's listener is directly reachable, an attacker who never
passed the edge can probe it; if the model backend is directly reachable, a
caller can skip the gate entirely and no authorization or receipt exists for
what it does. The required-path deployment closes both: the network offers no
direct route, and the gate refuses any production request that lacks a valid
assertion from the pinned edge issuer even so.

## The edge assertion check

Set `MEMBRANE_EDGE_AUTH_CONFIG` to an admin-owned YAML file before
`membrane gate start`:

```yaml
issuer: https://your-team.cloudflareaccess.com
audience: YOUR_POLICY_AUDIENCE_TAG
jwks_url: https://your-team.cloudflareaccess.com/cdn-cgi/access/certs
identity_claim: sub
header: cf-access-jwt-assertion
cache_ttl_secs: 300
```

With the file present, every production route (`/v1/chat/completions`,
`/v1/tools/invoke`, `/v1/spend/chat`, the operator IAC exchange and the
approval endpoints) must carry a valid RS256 assertion from the pinned
issuer and audience in the configured header. `/health` stays open for edge
and operator probes. The check is fail closed at every step: invalid
configuration stops startup; a missing, malformed, expired, wrong-key or
wrong-audience assertion denies the request before any IAC, caller-proof or
operator check runs; a failed JWKS refresh discards cached trust material
rather than falling back to it. Issuer and JWKS URLs must be HTTPS without
credentials or fragments; redirects are refused. The refusals are recorded
in the local decision log like other unauthenticated denials.

The assertion attests edge authentication of its holder, nothing more.
It is a bearer token: a stolen assertion replays from anywhere the network
allows, so it never replaces the network isolation that keeps untrusted
clients off the gate's listener. It grants no action authority and
never substitutes for the signed IAC, the per-request caller proof, identity
grants, liveness or journal checks; a request with a valid assertion and
nothing else is still refused. Because an assertion is per-session rather
than per-request, the caller proof remains the per-request binding - keep
both, and keep the network isolation, as independent layers.

JWKS trust is cached for `cache_ttl_secs` (300 by default), so a key revoked
at the edge keeps validating cached assertions until the cache expires. A
refresh is attempted when the cache expires or a request presents an unknown
key id, with a 30-second cooldown between attempts. A failed refresh
discards the cached keys rather than falling back to them: known assertions
keep working while the JWKS URL is down only until the cache expires, and
every production request denies after the first failed refresh until the URL
recovers. That is the deliberate availability tradeoff of failing closed.
Startup validates the configuration but does not fetch the JWKS; the first
request does.

The edge must own the assertion header. A production edge strips or
overwrites any client-supplied assertion header before forwarding, so only
assertions it issued reach the gate. The reference deployment's proxy does
not authenticate callers or mint assertions: the checked-in test key signs
test tokens and is public, which is exactly why it must never be trusted
anywhere real.

The example values match Cloudflare Access, which issues the assertion after
its own authentication and serves its keys at the pinned certs URL. Any
issuer that mints RS256 tokens for a pinned audience works the same way.
Protect the config file as operator authority; it is read at startup, so
restart to change it. Omit the variable to disable the check entirely.

`insecure_http_for_testing: true` additionally permits plain-HTTP issuer and
JWKS URLs. It exists for local and CI reference deployments only; never set
it anywhere real.

## Reference deployment

`deploy/edge/` runs the composition locally: an edge proxy on the client
network, and the gate, an example model backend, a JWKS stand-in and a relay
on an internal network with no published ports and no internet egress. The
client standpoint container holds no credentials and has no route to the
gate or the backend. A disposable test key signs assertions; it is checked in
for exactly this purpose and must never be trusted elsewhere.

The topology enforces the path only for clients confined to the client
network or off the host: the Docker host itself, and any container attached
to the internal network, can still reach the gate and the backend directly.
Keep internal-network membership minimal and treat host access as operator
access; the assertion check remains the second layer behind it.

`deploy/edge/verify.sh` builds the config, starts the stack and checks:

- direct connections from the client network to the gate and to the model
  backend fail;
- a request without an assertion is refused with its reason, as is one
  signed by the wrong key;
- a valid assertion without a caller proof is still refused;
- the fully authorized request crosses edge, gate and backend and returns
  the backend's marker, and replaying it is refused;
- the client environment carries no keys, tokens or upstream configuration;
- the refusals appear in the gate log.

Prerequisites: docker compose, jq, openssl, and the CLI plus the
`operator-request` example built
(`cargo build --locked -p membrane-cli --bin membrane --example operator-request`).
Select the gate image as in `deploy/pilot/` and run:

```bash
MEMBRANE_GATE_IMAGE=membrane-gate:local deploy/edge/verify.sh
```

The same check runs in CI on every push and pull request; a deployment
should only be called required-path after that run passes.

## Deploying it for real

Keep the reference topology and replace the stand-ins: terminate the client
network at your edge identity layer with its own authentication policy,
publish only the edge, pin its real issuer, audience and HTTPS JWKS URL, and
give the gate and its backends no public route. Verify with the same
expectations: a direct connection fails, and a request without the edge's
assertion fails even when everything else is valid.
