# Reference stack: self-hosted deployment with local models

This note describes a deployment in which every model call, tool call and receipt stays inside the operator's network. It is written for an integrator or an operator's platform team.

Every action carries an identity, an authorization and a receipt. The gate holds no standing privilege on behalf of an agent: each call needs a live, signed, time-bounded scope, and an action outside that scope is blocked and recorded.

Status: reference design. The gate's model path is exercised in the repository against a local llama.cpp backend (`deploy/gate`). The vLLM and Ollama sections below follow from the gate's OpenAI-compatible request shape and have not yet been run against those servers in a pilot. Hardware sizing is guidance, not a benchmark.

## Components

| Layer | Role | Notes |
|-------|------|-------|
| Agents | Callers | Each caller has its own key and an exact identity grant in the registry |
| Membrane gate | Authorization and receipts | Required path for in-scope agents; operator-held keys |
| Model server | Inference | vLLM, Ollama or llama.cpp, listening on an internal address reachable only by the gate |
| Receipt relay | Receipt bus | Operator-owned; runs inside the network |
| SIEM collector | Telemetry out | Splunk HEC, Datadog or NDJSON webhook; see [siem-export-hardened.md](siem-export-hardened.md) |

Request path: agent signs request, gate checks IAC, grant and caller proof, gate writes the receipt, gate forwards to the model server, response returns through the gate. A call without a valid scope never reaches the model server.

## Model server wiring

The gate posts to `<model_api_url>/v1/chat/completions` with a JSON body of `model`, `messages` and `stream: false`. Set `model_api_url` in the channel registry to the server base URL without the `/v1` suffix.

```yaml
permitted_channels:
  - local-llm
model_allowlist:
  - qwen2.5-7b-instruct
model_api_url: http://model-host:8000
```

| Server | Base URL example | Serving notes |
|--------|------------------|---------------|
| vLLM | `http://model-host:8000` | `vllm serve <weights> --served-model-name qwen2.5-7b-instruct` |
| Ollama | `http://model-host:11434` | Pull the model, then use its tag as the model name |
| llama.cpp | `http://llama:8080` | Used by `deploy/gate/docker-compose.yml` |

Constraints in the current gate, taken from `membrane-gate/src/proxy.rs`:

- The model name in the request must match the name the server exposes, and the same name must appear in the registry allowlist and the IAC.
- The gate sends no upstream credential. Do not enable a server API key; restrict the model server to the gate by network policy (loopback, a private network or a host firewall rule).
- Streaming is not supported. A request with `stream: true` is rejected.
- Response `message.content` must be a string.
- If the model server is unreachable the call fails; the gate does not substitute a canned reply unless `MEMBRANE_DEV_MOCK_MODEL=1` is set, which is for development only.

## Hardware tiers

Size by the largest model the workload needs, then by concurrent requests. VRAM is the first constraint: weights at 4-bit quantization need roughly half a byte per parameter plus working memory for the KV cache. Obtain current quotes from your hardware vendor.

| Tier | Typical use | GPU class | Model size range |
|------|-------------|-----------|------------------|
| Pilot | One team, low concurrency, ticket and code assistance | One workstation GPU with 24-48 GB VRAM | 7B-14B, or 32B at 4-bit |
| Department | Several teams, moderate concurrency | One or two data-center GPUs with 80 GB VRAM | 32B-70B at 4-bit or 8-bit |
| Facility | Many agents, larger models | Multi-GPU server (4-8 GPUs) with high-bandwidth interconnect | 70B and larger, tensor-parallel |

Common to all tiers: ECC system memory of at least 2x total VRAM, NVMe storage for weights and the receipt spool, redundant power, and a separate small host or VM for the gate and relay so the gate is not co-located with the inference workload.

## Model choices

Use open-weight models whose license permits the intended use. The repository's reference deployment uses Qwen2.5-0.5B-Instruct for smoke testing only. For real workloads, evaluate current instruction-tuned releases from the Qwen, Llama and Mistral families at the size the tier allows, and pin the exact weights file by hash in your deployment record. The Membrane does not depend on a model family; it authorizes by exact model identifier.

## Air-gapped operation

Nothing in the gate's request path requires an external service.

- Run the relay and the gate on internal hosts and point `MEMBRANE_RELAY_URL` at the internal relay.
- Mirror model weights and container images through an internal registry. Verify hashes after transfer.
- Do not enable the optional OpenTimestamps rollup; it uses external calendar servers. Use the hash-chained receipt spool and internal time sources for audit time.
- Export receipts to an internal SIEM collector. Use `fail_closed` mode if loss of the collector should stop agent traffic.
- Move operator-signed IACs and updates across the boundary by your approved transfer process.

Local-model checks to run before go-live:

1. Issue a short-lived IAC and send a signed request: expect a 200, a CP hash header and an allowed receipt.
2. Send a request naming a model outside the allowlist: expect a block and a receipt for the blocked call.
3. Stop the model server: expect an error, not a canned reply.
4. Let the IAC expire and repeat: expect a block.
5. Verify the receipt chain from the exported evidence.

Steps are in the [operator walkthrough](operator-walkthrough.md).

## Known limits

- The intent journal is single-instance; see [durable-journal.md](durable-journal.md).
- No live Okta or Entra exercise has been run for operator sign-in.
- Approval gates, where a held action executes only after a human approves it, are not built.
