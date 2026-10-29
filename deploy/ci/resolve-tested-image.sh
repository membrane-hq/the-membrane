#!/usr/bin/env bash
# Print the tested gate image reference (digest-pinned) for a commit, taken
# from GitHub's own run records - never from a tag.
#
# Trust boundary (every returned record is validated, not just queried):
# - Record must belong to THIS repository (head_repository.full_name; a
#   fork can produce a run with the same head_sha), name THIS commit
#   (head_sha), be the reviewed integration.yml workflow (path), and be a
#   manual dispatch (event; that workflow has no other trigger).
# - The release commit itself is verified to sit on protected main by the
#   calling workflow (publish-images.yml), for tag pushes and manual
#   dispatches alike.
# - A run qualifies only with conclusion=success on its LATEST attempt
#   (the listing's run_attempt), and the logs read are pinned to that same
#   attempt, so run record and log record cannot mix attempts. conclusion
#   reflects the whole run: the marker step runs before the bundle-encrypt
#   and artifact-upload steps, but a failure there marks the run failed
#   and excludes it here.
# - The marker is accepted only from its dedicated step ("Record the tested
#   gate image digest"), which runs after the signed manifest verifies, and
#   only if it names this repository's gate image with a full sha256
#   digest. Free-text elsewhere in the logs cannot inject a marker.
# - A run whose logs cannot be read fails closed (we cannot establish what
#   the newest green run tested), never silently skipped.
#
# Selection rule (explicit): validated runs are processed newest-created
# first. If the newest validated run did not succeed, refuse: the latest
# pilot attempt for this commit failed, so investigate and re-dispatch
# rather than release around it. Otherwise the newest successful run with
# a marker wins; if the newest successful run(s) have no marker they ran
# with publish=false (default mode pushes no image), and the most recent
# older successful run WITH a marker names its own tested digest. What is
# never promoted: a digest no successful publish-mode run recorded, a
# mutable tag, or bytes identified only by a tag (a failed publish-mode
# attempt may have pushed newer bytes under the sha-<commit> tag before
# failing; tags are never read here). The promoted digest is always one
# its own green run tested, and its registry object persists independent
# of what any later run pushed under tags.
#
# Usage: resolve-tested-image.sh <owner/repo> <commit-sha>
set -euo pipefail

REPO="${1:?usage: resolve-tested-image.sh <owner/repo> <commit-sha>}"
COMMIT="${2:?usage: resolve-tested-image.sh <owner/repo> <commit-sha>}"
WORKFLOW_PATH=".github/workflows/integration.yml"
STEP_NAME="Record the tested gate image digest"
MODE="${3:-release}"
[[ "$MODE" = release || "$MODE" = --provenance-json ]] || { echo "ERROR: invalid mode" >&2; exit 1; }

RUNS_JSON=$(gh api "repos/$REPO/actions/workflows/integration.yml/runs?head_sha=$COMMIT&per_page=10")

# Validate every returned record; query parameters are a hint, not proof.
mapfile -t RUNS < <(jq -r --arg repo "$REPO" --arg sha "$COMMIT" --arg path "$WORKFLOW_PATH" '
  .workflow_runs[]
  | select(.head_repository.full_name == $repo
           and .head_sha == $sha
           and .path == $path
           and .event == "workflow_dispatch")
  | [.id, .run_attempt, .conclusion, .head_branch] | @tsv' <<<"$RUNS_JSON")

if [ "${#RUNS[@]}" -eq 0 ]; then
  echo "ERROR: no valid pilot integration runs for commit $COMMIT in $REPO." >&2
  echo "  Dispatch 'Pilot integration (disposable)' with publish=true on this commit first." >&2
  exit 1
fi

NEWEST_CONCLUSION=$(cut -f3 <<<"${RUNS[0]}")
if [ "$NEWEST_CONCLUSION" != "success" ]; then
  echo "ERROR: the newest pilot run for $COMMIT concluded '$NEWEST_CONCLUSION', not success." >&2
  echo "  Failing closed: investigate and re-dispatch; do not release around a failed attempt." >&2
  exit 1
fi

for ENTRY in "${RUNS[@]}"; do
  RUN=$(cut -f1 <<<"$ENTRY"); ATTEMPT=$(cut -f2 <<<"$ENTRY")
  CONCLUSION=$(cut -f3 <<<"$ENTRY"); BRANCH=$(cut -f4 <<<"$ENTRY")
  [ "$CONCLUSION" = "success" ] || continue
  if ! LOG=$(gh run view "$RUN" --repo "$REPO" --attempt "$ATTEMPT" --log 2>/dev/null); then
    echo "ERROR: could not read logs for successful run $RUN attempt $ATTEMPT." >&2
    echo "  Failing closed: cannot establish what the newest green run tested." >&2
    exit 1
  fi
  MARKER=$(awk -F'\t' -v step="$STEP_NAME" '$2 == step {print $3}' <<<"$LOG" \
    | sed -n "s|.*TESTED_GATE_IMAGE=\(ghcr\.io/$REPO/membrane-gate@sha256:[0-9a-f]\{64\}\).*|\1|p" \
    | tail -1)
  if [ -n "$MARKER" ]; then
    echo "resolved tested image: run_id=$RUN attempt=$ATTEMPT branch=$BRANCH ref=$MARKER" >&2
    if [ "$MODE" = --provenance-json ]; then
      jq -n --arg ref "$MARKER" --arg repo "$REPO" --arg sha "$COMMIT" --arg run "$RUN" --arg attempt "$ATTEMPT" \
        '{ref:$ref, repository:$repo, commit:$sha, run_id:$run, run_attempt:$attempt, run_url:("https://github.com/"+$repo+"/actions/runs/"+$run)}'
    else
      echo "$MARKER"
    fi
    exit 0
  fi
  echo "run $RUN: success without a tested-image marker (publish=false); checking older runs" >&2
done

echo "ERROR: successful pilot runs for $COMMIT recorded no tested gate image." >&2
echo "  The green runs ran with publish=false; re-dispatch with publish=true." >&2
exit 1
