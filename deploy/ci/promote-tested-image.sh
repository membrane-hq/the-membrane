#!/usr/bin/env bash
# Promote the tested gate image to release tags by copying its exact
# manifest bytes through the GHCR registry API.
#
# A manifest digest is sha256 of the manifest bytes. This script downloads
# the source manifest bytes, verifies their hash equals the tested digest
# BEFORE any tag is written, PUTs those identical bytes under each release
# tag, then re-reads each tag and verifies the bytes again. Digest
# preservation is by construction and double-verified - no registry-tool
# behavior is assumed, and no mutation happens before correctness is
# established.
#
# Usage: GHCR_USER=... GHCR_TOKEN=... promote-tested-image.sh \
#          <owner/repo> <image-name> <digest-ref> <tag> [tag...]
set -euo pipefail

REPO="${1:?usage: promote-tested-image.sh <owner/repo> <image> <digest-ref> <tag>...}"
IMAGE="${2:?image name, e.g. membrane-gate}"
SRC="${3:?digest ref, e.g. ghcr.io/owner/repo/membrane-gate@sha256:...}"
shift 3
[ $# -ge 1 ] || { echo "ERROR: at least one tag is required" >&2; exit 1; }
: "${GHCR_USER:?set GHCR_USER}" "${GHCR_TOKEN:?set GHCR_TOKEN}"

EXPECTED="${SRC##*@}"
if ! grep -qE '^sha256:[0-9a-f]{64}$' <<<"$EXPECTED"; then
  echo "ERROR: source ref is not digest-pinned: $SRC" >&2
  exit 1
fi
case "$SRC" in
  ghcr.io/"$REPO"/"$IMAGE"@*) ;;
  *) echo "ERROR: source ref must be ghcr.io/$REPO/$IMAGE@sha256:..., got: $SRC" >&2; exit 1 ;;
esac

NS=$(tr '[:upper:]' '[:lower:]' <<<"$REPO")
ACCEPT='application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json'

TOKEN=$(curl -fsSL -u "$GHCR_USER:$GHCR_TOKEN" \
  "https://ghcr.io/token?scope=repository:$NS/$IMAGE:pull,push" | jq -r .token)
[ -n "$TOKEN" ] && [ "$TOKEN" != "null" ] || { echo "ERROR: no registry token" >&2; exit 1; }

WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT
curl -fsSL -H "Authorization: Bearer $TOKEN" -H "Accept: $ACCEPT" \
  -D "$WORK/headers" -o "$WORK/manifest.json" \
  "https://ghcr.io/v2/$NS/$IMAGE/manifests/$EXPECTED"
CTYPE=$(awk 'tolower($1) == "content-type:" {print $2}' "$WORK/headers" | tr -d '\r' | tail -1)
[ -n "$CTYPE" ] || { echo "ERROR: registry returned no manifest Content-Type" >&2; exit 1; }
case "$CTYPE" in
  application/vnd.docker.distribution.manifest.v2+json|application/vnd.oci.image.manifest.v1+json) ;;
  *) echo "ERROR: expected a single image manifest, got Content-Type: $CTYPE" >&2
     echo "  An index/manifest list is not the tested image; refusing to tag." >&2
     exit 1 ;;
esac

GOT="sha256:$(sha256sum "$WORK/manifest.json" | cut -d' ' -f1)"
if [ "$GOT" != "$EXPECTED" ]; then
  echo "ERROR: registry serves bytes hashing to $GOT for $SRC (expected $EXPECTED)." >&2
  echo "  Refusing to tag: the registry object is not the tested image." >&2
  exit 1
fi

for T in "$@"; do
  curl -fsSL -X PUT -H "Authorization: Bearer $TOKEN" -H "Content-Type: $CTYPE" \
    --data-binary @"$WORK/manifest.json" \
    "https://ghcr.io/v2/$NS/$IMAGE/manifests/$T" > /dev/null
  curl -fsSL -H "Authorization: Bearer $TOKEN" -H "Accept: $ACCEPT" \
    -o "$WORK/verify.json" "https://ghcr.io/v2/$NS/$IMAGE/manifests/$T"
  GOT="sha256:$(sha256sum "$WORK/verify.json" | cut -d' ' -f1)"
  if [ "$GOT" != "$EXPECTED" ]; then
    echo "ERROR: tag $T resolves to $GOT, not the tested $EXPECTED." >&2
    exit 1
  fi
  echo "promoted $SRC -> ghcr.io/$NS/$IMAGE:$T (digest verified before and after)"
done
