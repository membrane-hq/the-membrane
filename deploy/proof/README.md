# Deploy-boundary proof: fixture and protocol

This directory documents the disposable target fixture
(`membrane-proof-target`) and the fixed protocol the gate-side executor uses
to reach it. It is a deployment fixture: the seeded defect stands in for a
production weakness so the proof can show the gate's deploy boundary changing
real target behavior, without any eBPF or vulnerability-research claims.

## The fixture

`membrane-proof-target` is a tiny policy-gated HTTP service with a seeded
defect: with no policy installed, `POST /evaluate` accepts a `count` of any
size. The mitigation is a strict JSON policy artifact:

```json
{"schema_version": 1, "max_count": 100}
```

With the policy installed, a count above `max_count` is refused (422) and a
count within it still succeeds. Unknown keys, another schema version, an
out-of-range limit or an oversize body are rejected; the target never accepts
looser input than the executor was allowed to send.

Run it:

```sh
cargo run -p membrane-proof-target -- --listen 127.0.0.1:9301 \
    [--state-file /path/to/policy.bin]
```

`--state-file` persists the installed policy across restarts with atomic
tmp-then-rename writes, so the harness can test restart behavior.

## The fixed protocol

The executor may use only this surface. It receives validated typed input and
byte-verified artifact content, never caller-provided commands, paths or
addresses.

| Request | Behavior |
| --- | --- |
| `GET /health` | 200 liveness |
| `GET /state` | `{"policy_sha256", "image", "state_sha256"}` (digests only) |
| `GET /policy` | installed policy bytes, 404 on the default (defective) policy |
| `PUT /policy` | validate strictly, atomically replace, 204 |
| `DELETE /policy` | restore the default policy, 204 |
| `POST /evaluate {"count":N}` | 200, or 422 when policy refuses it |

The target state digest covers the current policy and the pinned fixture
image identifier:

```
state_sha256 = sha256("membrane-target-state/v1" NUL policy_sha256 NUL image)
```

The executor recomputes this digest locally from bytes it read back; it never
takes the target's word for its own state.

## Executor chain (slice 3)

`HttpPolicyExecutor` (`membrane-gate/src/deploy.rs`) on `deploy.apply`:

1. validate the artifact again itself (byte-verified is not policy-valid),
2. resolve the target base URL from trusted operator configuration
   (`TargetEndpoints`), never from the request,
3. read `GET /state` and compare against the request's reviewed
   `expected_prior_state_sha256`; a mismatch refuses before any write,
4. `PUT /policy` with the artifact bytes,
5. read the installed bytes back with `GET /policy` and `GET /state`,
   prove they are exactly the artifact, and return the locally recomputed
   observed state digest for the receipt.

`deploy.remove` is the same shape with `DELETE /policy` and a 404 read-back.

Failure classification is part of the boundary: anything that fails before
the write is sent (invalid artifact, prior-state mismatch, unreachable or
rejecting target) is a refusal, the reservation closes as refused, and the
route answers 403 blocked. Anything after the write is sent is uncertain: the
route answers 502, the reservation stays open for read-only reconciliation,
and nothing is retried blindly.

## Wiring the gate

The gate process enables the connector from trusted operator configuration,
both or neither:

```sh
MEMBRANE_DEPLOY_TARGETS="target-a=http://127.0.0.1:9301" \
MEMBRANE_DEPLOY_ARTIFACT_STORE=/path/to/artifact-store \
    membrane gate ...
```

Target IDs must also appear in the caller's registry and grant
`deploy_target_allowlist`; GitHub repo allowlist entries never authorize a
deploy. Operators stage artifacts into the store out of band; the store is
content-addressed and re-hashes bytes at dispatch.

## What this slice does not prove

- No adversarial or recovery harness yet (slice 4): no tamper, restart,
  partial-failure or reconciliation drills against a live target.
- No independent evidence verifier or runbook yet (slice 5): the receipt and
  journal records exist, but nothing yet lets a third party re-check a run
  without trusting the gate's own say-so.
- The fixture is not a production workload. The proof is about the boundary:
  typed requests, held approvals, byte-verified artifacts, prior-state
  comparison, and honest refusal versus uncertainty.
