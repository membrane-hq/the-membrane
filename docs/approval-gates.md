# Approval gates

An approval gate holds a tool call that is outside the caller's grant until a human operator approves or rejects it. An approved call runs once, under a one-shot grant bound to that exact call. The hold, the decision and the execution are each recorded in the receipt chain.

Every action carries an identity, an authorization and a receipt. An approval does not change that: it is an operator authorization for one call, and the caller keeps no standing privilege for the tool afterwards.

## Scope

Approval gates apply to `POST /v1/tools/invoke`. Chat and spend calls are unchanged. Gates are off unless the registry enables them.

## Configure

In the channel registry:

```yaml
approval:
  holdable_tools:
    - github.merge
  ttl_secs: 900
```

- `holdable_tools`: tools that may be held. An out-of-scope call to any other tool is blocked, as before.
- `ttl_secs`: how long a hold stays open, and how long an approval stays usable (1 to 86400, default 900).

Set `MEMBRANE_APPROVAL_STORE` to a file path for the durable approval store. The gate refuses to start with approval gates configured and no store path. Operator decisions use the operator OIDC configuration in [operator-oidc.md](operator-oidc.md); without it, nothing can be approved.

## Flow

1. The caller sends a signed tool call. The caller is authenticated, the model and scope are valid, the tool is holdable, and the caller's grant does not include the tool.
2. The gate checks everything else (scope, channel, model, repo allowlist, grant window). A call that fails any other check is blocked, not held.
3. The gate stores a hold bound to the caller, scope and exact request, publishes a blocked-action receipt that names the hold, and returns `202` with `status: "held"` and an `approval_id`. Nothing is dispatched. An identical retry while the hold is open returns the same hold.
4. An operator lists holds and decides:

   ```
   GET  /v1/approvals                       Authorization: Bearer <operator token>
   POST /v1/approvals/{id}/decision         Authorization: Bearer <operator token>
        {"decision": "approve", "note": "ticket 1234"}     # or "reject"
   ```

   The gate publishes a signed `membrane.approval.decision` event with the approver's OIDC subject, the call hash and the note before the decision takes effect. If publication fails, the hold stays pending.

   The local operator dashboard's approvals view calls the same routes: the operator pastes an OIDC token into the page, the dashboard relays it per request and stores nothing. See [operator-dashboard.md](operator-dashboard.md).
5. After approval, the caller sends the identical request again with a fresh caller proof. The gate consumes the approval, repeats every check except the tool allowlist, and dispatches. The execution receipt includes the approval ID, call hash and approver in its signed context, so the receipt chain links the hold, the decision and the call.
6. A second identical call is held again. Rejected, expired and consumed approvals never execute.

## What an approval binds

The call hash covers the authenticated caller, the IAC scope and the exact request body, including the operation ID. A changed body or operation ID needs a new approval. An approval waives only the tool allowlist check. The repo allowlist, model, scope, channels and grant window still apply when the call runs.

## Failure behavior

- If the approval store cannot be read or written, no hold opens and no approval is consumed. The call is blocked.
- An approval is marked consumed before dispatch. If dispatch fails before the call is sent, the operator approves again.
- Holds and approvals past `ttl_secs` read as expired.
- The `/v1/approvals` routes return 404 when gates are not enabled.

## Current limits

- Tool calls only. There is no hold for chat or spend.
- The caller retries after approval; the gate does not execute on approval alone.
- Approvers are OIDC operators mapped in the operator configuration. There is no separate approver role and no multi-approver rule. The dashboard approvals view relays the operator's token; it holds no authority of its own.
- Hold policy is read at startup. Changing `approval` in the registry needs a gate restart.
- The store is one file on one gate instance.
- The decision routes are covered by unit tests for the store and the call path. They have not been exercised against a live Okta or Entra tenant.
