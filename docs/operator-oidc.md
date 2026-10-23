# Operator identity through an IdP

The gate can authenticate an operator's RS256 JWT from Okta, Entra ID or
another configured issuer. No browser login, client secret or OAuth callback
is implemented. Your existing IdP client obtains an access token for the gate's
operator API. A token for another API, such as Microsoft Graph, is not usable.

## What changes

`POST /v1/operator/iac` exchanges an operator bearer token for a gate-signed,
caller-bound IAC. The IdP claim maps to the existing trusted operator public
key. Only exact, explicitly mapped identities can issue IACs. Every mapped
identity has full issuance authority within the caller grants, not a separate
role. Do not map an entire group or a mutable email address to that authority.

Operators using this exchange do not need the signing secret on their clients.
The gate still needs its [local signing key](signing-key.md) for IAC signatures, receipts and the
bus. Existing locally signed IACs remain the bootstrap/break-glass path. This
is operator federation, not an alternative to agent caller keys or caller
proofs. Chat and tool endpoints still require the existing signed IAC,
caller proof, grants, allowlists, liveness and journal checks.

## Configure

1. Identify the gate's existing signing public key and the immutable identity
   claim for each operator. Use the existing key tooling; never put the secret
   key in this config. Add explicit caller grants to your channel registry.
2. Obtain the issuer and `jwks_uri` from the IdP's trusted discovery document.
   Copy their exact values, including issuer trailing slashes if present.
   The gate intentionally does not discover URLs from tokens.
3. Create an admin-owned YAML file, for example `/etc/membrane/operator-oidc.yaml`:

```yaml
issuer: https://your-org.okta.com/oauth2/default
audience: https://membrane.example/operator
jwks_url: https://your-org.okta.com/oauth2/default/v1/keys
identity_claim: sub
cache_ttl_secs: 300
operators:
  immutable-operator-subject: "REPLACE_WITH_GATE_SIGNING_PUBLIC_KEY"
```

All mappings must target the gate's existing trusted signing public key;
foreign keys, empty maps, unknown config fields and malformed settings fail
startup. Issuer and JWKS URLs must be HTTPS, without credentials or fragments.
Redirects are refused. Protect this file as operator authority: adding a
mapping grants issuance rights. It is read at startup; restart to change it.
Caller grants are still re-read for each issuance and each production request.

4. Set `MEMBRANE_OPERATOR_OIDC_CONFIG` to that file before your normal
   `membrane gate start` command. Keep the existing relay, registry, signing-key
   and bootstrap IAC settings. Omit the variable to disable OIDC entirely.
5. Serve the production listener behind TLS. Bearer tokens are credentials;
   never place them in URLs, access logs or tickets. Add request rate limits
   at the reverse proxy and keep the telemetry listener loopback-only.

### Okta

Use a **custom authorization server**, not the org authorization server.
Set its audience to the gate operator API audience, configure an access policy
for approved clients/operators, and issue short-lived access tokens.
Read the issuer and JWKS URL from that server's metadata. The example above
uses the common `default` custom server layout; replace it with your values.
Map an immutable `sub`, or an admin-controlled immutable custom string claim
if the server's subject format is not suitable. Confirm the exact claim value
from a verified token in your own environment.

### Microsoft Entra ID

Use a single-tenant API app registration for the gate and v2 access tokens.
Configure the API to receive v2 tokens, permit only the intended client apps,
and issue tokens for this API, not Graph. Copy the tenant-specific metadata
issuer and JWKS URL. Do not use `common` or `organizations` for this release.
For v2 access tokens, the configured audience is the API's application/client
ID GUID, not the `api://` scope URI used by clients to request a token.

```yaml
issuer: https://login.microsoftonline.com/TENANT_GUID/v2.0
audience: API_APPLICATION_CLIENT_ID_GUID
jwks_url: COPY_JWKS_URI_FROM_TENANT_SPECIFIC_METADATA
identity_claim: oid
cache_ttl_secs: 300
operators:
  OPERATOR_OBJECT_ID: "REPLACE_WITH_GATE_SIGNING_PUBLIC_KEY"
```

`oid` is tenant-bound by the exact issuer. For a machine identity, explicitly
map its service-principal object ID, not a general `azp`/client-ID claim that
can occur in delegated tokens. Client authorization, app assignments and
conditional access remain IdP policy responsibilities. If metadata requires
an application-specific JWKS URI for custom signing keys, copy that URI.
Keys with incompatible issuer constraints in JWKS are excluded; the Entra `{tenantid}`
template is substituted only with the configured fixed tenant GUID.

## Exchange

With your approved client, obtain a token for the configured audience. Send:

```http
POST /v1/operator/iac
Authorization: Bearer <operator-access-token>
Content-Type: application/json

{
  "caller_pubkey": "<64 lowercase hex characters>",
  "scope_id": "pilot-scope",
  "model": "sha256:your-model",
  "tools": ["github.comment"],
  "ttl_secs": 120
}
```

The response is the normal signed IAC JSON. Store it and use the existing
caller-proof request protocol. The exchange never calls a model or tool.
It refuses scopes, models, channels or tools outside that caller's live grant,
revoked callers, malformed keys and TTLs outside 1-300 seconds. It inherits
registry forbidden exports, binds the current chain head, and limits validity
to the token expiry and grant expiry. The IAC's inclusive `valid_until` is
one second before those exclusive boundaries. Issuance is recorded in the
bounded decision log with the mapped operator, without logging token/claims.

## Failure, caching and rotation

- Required claims: `iss`, `aud`, `exp`, `sub`; `nbf` is checked when present.
  Signature and algorithm must be RS256, and `kid` must select an RSA signing
  key. Issuer and audience match exactly; audience arrays are supported.
  There is no clock-skew grace. Synchronize the gate and IdP clocks.
- JWKS is fetched on demand and cached for 300 seconds by default (allowed
  range 30-3600). An unknown `kid` refreshes the set, subject to a 30-second
  refresh cooldown. A new key seen during cooldown denies until a later
  request. Refresh replaces the set, so removed keys no longer validate.
  Rotation that reuses the same `kid` takes effect at cache expiry.
- A fresh cached key can validate offline until the TTL ends. This is bounded
  cached trust, not a live IdP availability check on every call. After expiry,
  or when a refresh is required, network/HTTP/JSON failure clears old trust
  material and denies. There is no stale-cache or unsigned-token fallback.
- Unconfigured OIDC denies the exchange. Invalid configured settings prevent
  startup. JWKS outage denies OIDC when fresh trust cannot be established;
  separately authenticated local-key IACs still work.
- Fetches are coalesced, have a five-second timeout, refuse redirects, and
  cap JWKS at 256 KiB/128 keys. Tokens are capped at 16 KiB. Duplicate key IDs
  and keys restricted to encryption or incompatible algorithms are refused.

## Limits

No browser SSO UI, OAuth token acquisition, refresh-token storage, discovery
automation, multi-tenant issuer templates, roles/groups, per-operator delegated
scope policy, SCIM, MFA/ACR policy enforcement, token introspection or instant
IdP revocation is included. Configure IdP access policy accordingly. Valid
JWTs can be reused until expiry; this is bearer-token authentication, not
proof of possession. Use short lifetimes. Already issued IACs expire within
five minutes and cannot outlive the issuing token; caller-grant revocation
still blocks production calls immediately. Mapping changes require restart.
The issuance log is observational and bounded, not a durable signed issuance
receipt. Existing gate receipt/signing authority is unchanged.

Tests use local mock JWKS and synthetic RSA keys. They cover claims, rotation,
outages, mapping, issuance bounds and the unchanged keypair path. No live
Okta or Entra tenant has been exercised.

Provider references:
- https://developer.okta.com/docs/guides/validate-access-tokens/main/
- https://learn.microsoft.com/en-us/entra/identity-platform/access-tokens
- https://learn.microsoft.com/en-us/entra/identity-platform/claims-validation
