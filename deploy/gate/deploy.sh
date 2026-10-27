#!/usr/bin/env bash
# Deploy Membrane gate + llama.cpp on relay-2. Idempotent.
#
# Default: run the exact tested gate image. Set MEMBRANE_GATE_IMAGE to the
# digest-pinned reference from a signed pilot run manifest
# (ghcr.io/membrane-hq/the-membrane/membrane-gate@sha256:...); the host
# pulls that digest and docker verifies the content against it. Mutable
# tags are refused. --build-local rebuilds from synced source instead
# (development only; the result is not the tested image).
#
# Requires NOSTR_NSEC in remote /opt/membrane/gate/.env (chmod 600).
# While the ghcr.io package is private, the host also needs
# docker login ghcr.io with a token that can read packages.
# Usage: MEMBRANE_GATE_IMAGE=<ref> ./deploy.sh [ssh-host] [--build-local]
set -euo pipefail

HOST="relay-2"
BUILD_LOCAL=0
for arg in "$@"; do
  case "$arg" in
    --build-local) BUILD_LOCAL=1 ;;
    *) HOST="$arg" ;;
  esac
done
REMOTE_DIR="${MEMBRANE_REMOTE_DIR:-/opt/membrane/gate}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
MODEL_URL="https://huggingface.co/Qwen/Qwen2.5-0.5B-Instruct-GGUF/resolve/main/qwen2.5-0.5b-instruct-q4_k_m.gguf"
MODEL_FILE="qwen2.5-0.5b-instruct-q4_k_m.gguf"

if [[ "$BUILD_LOCAL" = 0 ]]; then
  if [[ -z "${MEMBRANE_GATE_IMAGE:-}" ]]; then
    echo "ERROR: MEMBRANE_GATE_IMAGE is not set."
    echo "  Take the digest-pinned reference (membrane-gate@sha256:...) from the"
    echo "  signed run manifest of a green pilot run, or pass --build-local for a"
    echo "  development build that is not the tested image."
    exit 1
  fi
  if [[ "$MEMBRANE_GATE_IMAGE" != *@sha256:* ]]; then
    echo "ERROR: MEMBRANE_GATE_IMAGE must be digest-pinned (...@sha256:...), got: $MEMBRANE_GATE_IMAGE"
    echo "  A mutable tag can move after the run manifest was signed; a digest cannot."
    exit 1
  fi
else
  MEMBRANE_GATE_IMAGE="membrane-gate:local"
fi

echo "==> Deploying Membrane gate to ${HOST}:${REMOTE_DIR}"
echo "==> Gate image: ${MEMBRANE_GATE_IMAGE}"

ssh -o BatchMode=yes "$HOST" "mkdir -p '$REMOTE_DIR'"

rsync -az \
  "$SCRIPT_DIR/channel-registry.prod.yaml" \
  "$SCRIPT_DIR/docker-compose.yml" \
  "$SCRIPT_DIR/iac.prod.json" \
  "$HOST:$REMOTE_DIR/"

if [[ "$BUILD_LOCAL" = 1 ]]; then
  rsync -az \
    "$SCRIPT_DIR/Dockerfile" \
    "$REPO_ROOT/Cargo.toml" \
    "$REPO_ROOT/Cargo.lock" \
    "$REPO_ROOT/membrane-core" \
    "$REPO_ROOT/membrane-gate" \
    "$REPO_ROOT/membrane-cli" \
    "$HOST:$REMOTE_DIR/build-context/"
fi

if [[ -f "$SCRIPT_DIR/.env" ]]; then
  scp -q "$SCRIPT_DIR/.env" "$HOST:$REMOTE_DIR/.env"
  ssh -o BatchMode=yes "$HOST" "chmod 600 '$REMOTE_DIR/.env'"
elif ! ssh -o BatchMode=yes "$HOST" "test -f '$REMOTE_DIR/.env'"; then
  echo "ERROR: missing $REMOTE_DIR/.env on host (NOSTR_NSEC=...)"
  echo "  doppler run --project dojopop --config prd_zorie -- bash -c 'printf \"NOSTR_NSEC=%s\\nMEMBRANE_RELAY_URL=wss://membrane-relay.dojopop.live\\n\" \"\$NOSTR_NSEC\" > deploy/gate/.env'"
  exit 1
fi

ssh -o BatchMode=yes "$HOST" bash -s <<REMOTE
set -euo pipefail
REMOTE_DIR='$REMOTE_DIR'
MODEL_URL='$MODEL_URL'
MODEL_FILE='$MODEL_FILE'
export MEMBRANE_GATE_IMAGE='$MEMBRANE_GATE_IMAGE'
BUILD_LOCAL='$BUILD_LOCAL'

if ! docker compose version >/dev/null 2>&1; then
  apt-get update -qq && apt-get install -y -qq docker-compose-v2
fi

cd "\$REMOTE_DIR"

# Ensure GGUF model in docker volume
if ! docker run --rm -v membrane-llama-models:/models alpine \
  test -f "/models/\$MODEL_FILE" 2>/dev/null; then
  echo "==> Downloading \${MODEL_FILE} (~400MB) into llama-models volume..."
  docker run --rm --user root \
    -v membrane-llama-models:/models \
    curlimages/curl:8.12.1 -fL \
    "\$MODEL_URL" -o "/models/\$MODEL_FILE"
fi

if [[ "\$BUILD_LOCAL" = 1 ]]; then
  # Development path: build from synced source (not the tested image)
  docker build -f Dockerfile -t membrane-gate:local build-context/
else
  # Pull the exact tested digest; docker verifies content against it
  docker compose -p membrane-gate pull gate || {
    echo "ERROR: pull failed for \$MEMBRANE_GATE_IMAGE"
    echo "  If the ghcr.io package is private, run: docker login ghcr.io"
    exit 1
  }
  actual=\$(docker image inspect "\$MEMBRANE_GATE_IMAGE" -f '{{index .RepoDigests 0}}')
  [[ "\$actual" = "\$MEMBRANE_GATE_IMAGE" ]] || {
    echo "ERROR: pulled image digest mismatch: \$actual"
    exit 1
  }
fi

docker compose -p membrane-gate up -d --remove-orphans
docker compose -p membrane-gate ps

mkdir -p /opt/membrane/bin
cid=\$(docker create "\$MEMBRANE_GATE_IMAGE")
docker cp "\$cid:/usr/local/bin/membrane" /opt/membrane/bin/membrane
docker rm "\$cid" >/dev/null
chmod 755 /opt/membrane/bin/membrane

echo "==> Gate health (tailnet): curl http://${HOST}:8787/health"
REMOTE

echo "==> Done."
