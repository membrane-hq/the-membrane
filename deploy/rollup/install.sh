#!/usr/bin/env bash
# Install Membrane daily rollup timer on relay-2.
#
# Prerequisite: Docker on the target host; builds a separate ots-enabled binary.
# Usage: ./install.sh [ssh-host]
set -euo pipefail

HOST="${1:-relay-2}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REMOTE_DIR="/opt/membrane/rollup"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

echo "==> Installing rollup timer on ${HOST}"

ssh -o BatchMode=yes "$HOST" "mkdir -p '$REMOTE_DIR' /var/lib/membrane/rollup /opt/membrane/bin"

rsync -az \
  "$SCRIPT_DIR/membrane-rollup.service" \
  "$SCRIPT_DIR/membrane-rollup.timer" \
  "$HOST:$REMOTE_DIR/"

# Build OTS separately. Gate deploys never enable it or overwrite this binary.
rsync -az \
  "$REPO_ROOT/Cargo.toml" "$REPO_ROOT/Cargo.lock" \
  "$REPO_ROOT/membrane-core" "$REPO_ROOT/membrane-gate" \
  "$REPO_ROOT/membrane-cli" "$REPO_ROOT/membrane-dashboard" \
  "$REPO_ROOT/membrane-advisor" \
  "$HOST:$REMOTE_DIR/build-context/"
ssh -o BatchMode=yes "$HOST" "mkdir -p '$REMOTE_DIR/build-context/deploy/rollup'"
rsync -az "$SCRIPT_DIR/Dockerfile" "$HOST:$REMOTE_DIR/build-context/deploy/rollup/"
ssh -o BatchMode=yes "$HOST" bash -s <<'BUILD'
set -euo pipefail
cd /opt/membrane/rollup/build-context
docker build -f deploy/rollup/Dockerfile -t membrane-rollup:local .
cid=$(docker create membrane-rollup:local)
trap 'docker rm "$cid" >/dev/null' EXIT
docker cp "$cid:/usr/local/bin/membrane" /opt/membrane/rollup/membrane
chmod 755 /opt/membrane/rollup/membrane
/opt/membrane/rollup/membrane rollup --help >/dev/null
BUILD

if [[ -f "$SCRIPT_DIR/../gate/.env" ]]; then
  scp -q "$SCRIPT_DIR/../gate/.env" "$HOST:$REMOTE_DIR/.env"
  ssh -o BatchMode=yes "$HOST" "chmod 600 '$REMOTE_DIR/.env'"
elif ! ssh -o BatchMode=yes "$HOST" "test -f '$REMOTE_DIR/.env'"; then
  echo "ERROR: missing $REMOTE_DIR/.env (copy from deploy/gate/.env)"
  exit 1
fi

ssh -o BatchMode=yes "$HOST" bash -s <<REMOTE
set -euo pipefail
# Use local attestation bus from host (systemd runs outside Docker)
if grep -q MEMBRANE_RELAY_URL "$REMOTE_DIR/.env"; then
  sed -i 's|^MEMBRANE_RELAY_URL=.*|MEMBRANE_RELAY_URL=ws://127.0.0.1:7778|' "$REMOTE_DIR/.env"
else
  echo 'MEMBRANE_RELAY_URL=ws://127.0.0.1:7778' >> "$REMOTE_DIR/.env"
fi

cp "$REMOTE_DIR/membrane-rollup.service" /etc/systemd/system/
cp "$REMOTE_DIR/membrane-rollup.timer" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now membrane-rollup.timer
systemctl status membrane-rollup.timer --no-pager
REMOTE

echo "==> Rollup timer enabled (00:15 UTC daily)"
echo "    Manual run: ssh $HOST 'systemctl start membrane-rollup.service'"
