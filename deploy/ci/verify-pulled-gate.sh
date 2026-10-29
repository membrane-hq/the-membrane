#!/usr/bin/env bash
# Bind the running gate and loopback endpoint to the pulled registry image.
set -euo pipefail
REF="${1:?digest-pinned image reference required}"
CID="${2:?compose gate container ID required}"
[[ "$CID" =~ ^[0-9a-f]{12,64}$ ]] || { echo 'ERROR: expected one container ID' >&2; exit 1; }
EXPECTED=$(docker image inspect "$REF" --format '{{.Id}}')
[[ "$EXPECTED" =~ ^sha256:[0-9a-f]{64}$ ]] || { echo 'ERROR: invalid pulled image ID' >&2; exit 1; }
docker container inspect "$CID" | jq -e --arg image "$EXPECTED" --arg ref "$REF" '
  length == 1 and .[0].Image == $image and .[0].Config.Image == $ref
  and .[0].State.Running == true and .[0].State.Pid > 0
  and .[0].RestartCount == 0
  and (.[0].NetworkSettings.Ports["8787/tcp"] == [{"HostIp":"127.0.0.1","HostPort":"8787"}])
' >/dev/null || { echo 'ERROR: running gate image or loopback endpoint mismatch' >&2; exit 1; }
echo "running gate verified: container=$CID image=$EXPECTED ref=$REF"
