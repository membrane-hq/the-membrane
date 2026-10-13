# The Membrane

**A fail-closed authorization gateway for AI agents with production / operational write access.**

Every model and tool call needs a live, signed, time-bounded scope; each action writes a tamper-evident receipt; broken continuity blocks or severs the agent.

Self-host the gate, hold your own keys, and check authorization before agents reach your systems. Keep receipts for the actions that pass through it.

---

## Product overview

Operators are putting AI agents on paths that mutate systems: agents that merge code, edit tickets, change infrastructure, and touch operational data. When an agent does something wrong, teams are left with scattered logs and third-party chat histories-and no way to prove which model, which context, which policy, and which person or parent agent actually authorized the action.

The Membrane is the enforcement and evidence layer that sits directly in front of those agents. Every model call and every tool action must carry a live, signed authorization that names the allowed model, the allowed tools, and the scope of the task. Each action is written to a tamper-evident, hash-linked receipt chain. If the authorization is missing, expired, or out of scope-or if the model or tool is swapped mid-task-the Membrane blocks the action and can sever the agent instantly.

Membrane receipts can be exported as vendor-neutral JSON Lines or OCSF-inspired JSON for an existing SIEM, SOC, or SOAR. The Membrane produces high-integrity authorization telemetry; those systems ingest, correlate, and respond to it. SIEM export is telemetry *out*-not a monitoring product.

The Membrane enforces and proves the traffic that runs through it. Deploy it as the required path for in-scope agents so approved actions are provable and unauthorized ones never reach production.

---

## Deployment

The Membrane is for operators giving agents write access to systems they control. Run the gate in your own environment, with your own keys, registry and connectors. Authorization stays with the operator.

## Software and demo

The gate, CLI, receipt and attestation components, read-only dashboard and deterministic advisor are working software. The advisor proposes changes for human review; it does not edit policy or grant access.

The demo walks through the gate's checks and receipt chaining with ephemeral keys and simulated tool effects. Production integrations require configured backends and supported connectors; research proposals in the whitepaper are not shipped integrations.

---

## Problem

Organizations are granting AI agents write access to production and operational systems, but existing logs are editable, incomplete, and can't prove an action was authorized by an unexpired policy-so incident reconstruction is slow and unreliable. High-assurance operators cannot outsource that continuity to an opaque vendor plane.

## Solution

A fail-closed gateway that requires a live, signed authorization for every model and tool call, records each action in a tamper-evident receipt chain, and blocks or severs the agent the moment the chain breaks-run under keys and infra the operator controls.

## How it differs

1. **It enforces, it doesn't just watch.** Observability tools explain what an agent did after the fact. The Membrane is an inline control point that refuses unauthorized actions before they reach production.

2. **Authorization is bound to the action, not the prompt.** Every action carries a signed policy naming the exact model, tools, and scope, linked into a tamper-evident receipt chain. A silent model or tool swap breaks the chain and is blocked.

3. **Incident reconstruction with exportable evidence under your keys.** Because approvals and actions are hash-linked, operators can trace any action to its authorizing policy and issuer, and hand auditors a signed evidence pack-no dependence on a provider's mutable logs or control plane.

---

## Demo narrative

1. **Grant scope.** An operator issues a 15-minute authorization for a support agent: model X, tools limited to *comment on tickets* and *post to Slack*, bound to one task.
2. **Approved action.** The agent posts a ticket comment. The console shows a green, linked receipt: policy → model → tool, all matching.
3. **Blocked swap.** The agent tries to use a different model, or reach for *merge to main*-outside the authorization. The Membrane blocks it; a red receipt shows exactly why.
4. **Expiry / sever.** The authorization expires (or the operator selects "sever"). The next tool call fails closed; the demo shows the denial.
5. **Reconstruct.** Open the timeline, click any action, and see the model, context scope, policy, and issuer behind it-no log spelunking.
6. **Export evidence.** One click produces a signed evidence pack; verify the hash chain offline in seconds.

Local walkthrough: [demo.md](demo.md) (`cargo run -p membrane-cli --features demo -- demo`). For external tool execution, configure the production gate with a supported connector ([github-connector.md](github-connector.md)).

---

## Initial use case

Tool-using agents that can change production or operational systems. The operator needs to check which model, tool and policy authorize each action, keep the evidence, and stop access when authorization fails. Route those calls through the gate and configure only the connectors and grants the task requires.
