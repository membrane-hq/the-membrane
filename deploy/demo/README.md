# Public demo sandbox

Container deployment for the simulation-only dashboard at
`https://demo.themembrane.org`.

This deployment is intentionally separate from every production Membrane
component. It requires no environment file and must never receive
`NOSTR_NSEC`, `NGIT_NSEC`, relay credentials, model credentials, customer
data, or access to a production network.

## Isolation model

- A fresh ephemeral signing key and `memory://` bus are created on process start.
- Each browser receives an opaque, `HttpOnly`, `SameSite=Strict` session cookie.
- Chain, authorization, timeline, and evidence state are isolated per session
  and expire after 30 minutes; restart clears all state.
- Jira, Slack, and GitHub results are fixed local simulations. The Rust
  container uses an internal network with no outbound route. A separate,
  unprivileged ingress sidecar can only proxy loopback traffic to that network.
- Do **not** set `MEMBRANE_GITHUB_TOKEN` / `GITHUB_TOKEN` or a non-empty
  `github_repo_allowlist` on this host. External tool connectors belong on operator
  installs only (`membrane gate start`), not the public sandbox.
- The service binds only to host loopback. Publish it through an authenticated
  HTTPS edge tunnel; do not expose port 8790 directly.
- The process runs unprivileged with a read-only filesystem, dropped
  capabilities, resource limits, request-size limits, rate limits, same-origin
  enforcement, and restrictive browser security headers.

## Deploy

The target must already provide Docker Compose and an HTTPS edge tunnel.

```bash
./deploy/demo/deploy.sh <ssh-host>
```

Add the edge route `demo.themembrane.org` to
`http://127.0.0.1:8790`. Do not add any production service or network to the
`membrane-demo` Compose project.

## Verify

```bash
curl --fail https://demo.themembrane.org/health
curl -I https://demo.themembrane.org/
```

Then complete the browser flow: issue → allowed action → blocked tool →
blocked model → sever → post-sever block → export → verify.
