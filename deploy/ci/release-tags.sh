#!/usr/bin/env bash
# Compute release tags for a gate-image promotion.
#   release-tags.sh workflow_dispatch <any>  -> edge
#   release-tags.sh push v1.2.3              -> "1.2.3 1.2"
#   release-tags.sh push v1.2                -> "1.2"
set -euo pipefail
EVENT="${1:?usage: release-tags.sh <event_name> <ref_name>}"
REF_NAME="${2:?usage: release-tags.sh <event_name> <ref_name>}"
if [ "$EVENT" = "workflow_dispatch" ]; then
  echo "edge"
else
  VERSION="${REF_NAME#v}"
  case "$VERSION" in
    *.*.*) echo "$VERSION ${VERSION%.*}" ;;
    *)     echo "$VERSION" ;;
  esac
fi
