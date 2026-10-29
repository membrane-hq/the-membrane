#!/usr/bin/env bash
# Cold-install check only. Never builds, pushes, tags or starts a service.
# Input must already be resolved from a green run by resolve-tested-image.sh.
set -euo pipefail
REPO="${1:?usage: pull-tested-image.sh <owner/repo> <digest-ref>}"
REF="${2:?digest-pinned gate image reference required}"
PREFIX="ghcr.io/$REPO/membrane-gate@sha256:"
case "$REF" in
  "$PREFIX"*) ;;
  *) echo "ERROR: expected this repository's digest-pinned gate image" >&2; exit 1 ;;
esac
DIGEST="${REF#"$PREFIX"}"
[[ "$DIGEST" =~ ^[0-9a-f]{64}$ ]] || { echo "ERROR: invalid sha256 digest" >&2; exit 1; }
# A fresh job must not reuse the publisher's local image. Fail if this
# digest is already cached; leave other host images untouched.
docker info >/dev/null
if docker image inspect "$REF" > /dev/null 2>&1; then
  echo "ERROR: cold-install requires the target digest to be absent locally" >&2; exit 1
fi
# Ensure an inspect error was not a dead daemon before treating it as absence.
docker info >/dev/null
docker pull "$REF"
REPO_DIGESTS=$(docker image inspect "$REF" --format '{{json .RepoDigests}}')
jq -e --arg ref "$REF" 'type == "array" and index($ref) != null' <<<"$REPO_DIGESTS" >/dev/null \
  || { echo "ERROR: pulled image does not report the expected registry digest" >&2; exit 1; }
echo "cold pull verified: $REF"
