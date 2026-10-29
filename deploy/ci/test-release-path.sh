#!/usr/bin/env bash
# Fixture tests for the tested-image release path. No docker, registry or
# GitHub access: gh, curl, ssh, rsync, scp and docker are stubbed per case.
#
# resolve-tested-image.sh: green run, attempt pinning, wrong-step marker
#   (log injection), failed run, green run without publish marker, stale
#   fallback policy, mutable-tag marker, other-repo marker, newest-first.
# release-tags.sh: semver pair, short semver, dispatch edge.
# promote-tested-image.sh: happy path with byte-exact PUTs, source-bytes
#   mismatch refused before any mutation, post-PUT verification failure,
#   non-digest source, wrong-repo source.
# deploy/gate/deploy.sh: missing ref, mutable-tag refusal, digest pull
#   success, post-pull digest mismatch, --build-local development path.
set -u
cd "$(dirname "$0")/../.."

REPO="membrane-hq/the-membrane"
COMMIT="0123456789abcdef0123456789abcdef01234567"
DIGEST="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
DIGEST2="cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
OTHER_DIGEST="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
REF="ghcr.io/$REPO/membrane-gate@sha256:$DIGEST"
REF2="ghcr.io/$REPO/membrane-gate@sha256:$DIGEST2"
OTHER_REF="ghcr.io/$REPO/membrane-gate@sha256:$OTHER_DIGEST"

PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); echo "ok   - $1"; }
bad()  { FAIL=$((FAIL+1)); echo "FAIL - $1"; }

T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT

STUB="$T/bin"; mkdir -p "$STUB"

# gh stub: "api" answers with $STUB_RUNS_JSON; "run view" records the
# attempt used and serves $STUB_LOG_DIR/<id>.log
cat > "$STUB/gh" <<'SH'
#!/usr/bin/env bash
if [ "$1" = "api" ]; then cat "$STUB_RUNS_JSON"; exit 0; fi
if [ "$1" = "run" ] && [ "$2" = "view" ]; then
  id="$3"; shift 3; attempt=""
  while [ $# -gt 0 ]; do
    [ "$1" = "--attempt" ] && attempt="$2"
    shift
  done
  echo "view $id attempt=$attempt" >> "$STUB_VIEW_LOG"
  cat "$STUB_LOG_DIR/$id.log" 2>/dev/null || exit 1
  exit 0
fi
exit 1
SH

# curl stub for GHCR: token endpoint, manifest GET (source by digest /
# verify by tag) and manifest PUT (recorded with body hash)
cat > "$STUB/curl" <<'SH'
#!/usr/bin/env bash
out=""; headers=""; method="GET"; data=""; url=""
while [ $# -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift 2 ;;
    -D) headers="$2"; shift 2 ;;
    -X) method="$2"; shift 2 ;;
    --data-binary) data="${2#@}"; shift 2 ;;
    -u|-H) shift 2 ;;
    -fsSL|-f|-s|-S|-L) shift ;;
    *) url="$1"; shift ;;
  esac
done
case "$url" in
  *"/token?"*) printf '%s' '{"token":"stub-token"}'; exit 0 ;;
  *"/manifests/"*)
    name="${url##*/manifests/}"
    if [ "$method" = "PUT" ]; then
      echo "PUT $name $(sha256sum "$data" | cut -d' ' -f1)" >> "$STUB_PUT_LOG"
      exit 0
    fi
    [ -n "$headers" ] && printf 'HTTP/2 200\r\nContent-Type: %s\r\n' "${STUB_CTYPE:-application/vnd.docker.distribution.manifest.v2+json}" > "$headers"
    case "$name" in
      sha256:*) bytes="$STUB_GET_SRC_BYTES" ;;
      *)        bytes="$STUB_GET_TAG_BYTES" ;;
    esac
    if [ -n "$out" ]; then printf '%s' "$bytes" > "$out"; else printf '%s' "$bytes"; fi
    exit 0 ;;
esac
exit 1
SH

cat > "$STUB/rsync" <<'SH'
#!/usr/bin/env bash
exit 0
SH
cp "$STUB/rsync" "$STUB/scp"

# ssh stub: string commands via eval; "bash -s" runs the heredoc with
# stubbed docker/mkdir/chmod first on PATH. Stdin saved for assertions.
cat > "$STUB/ssh" <<'SH'
#!/usr/bin/env bash
shift; shift; shift  # -o BatchMode=yes <host>
if [ "$1" = "bash" ]; then
  mkdir -p "$MEMBRANE_REMOTE_DIR"
  cat > "$MEMBRANE_REMOTE_DIR/remote-invocation.sh"
  PATH="$DOCKER_STUB:$PATH" bash "$MEMBRANE_REMOTE_DIR/remote-invocation.sh"
  exit $?
fi
eval "$1"
SH

DSTUB="$T/dockerbin"; mkdir -p "$DSTUB"
cat > "$DSTUB/docker" <<'SH'
#!/usr/bin/env bash
case "$1" in
  image)  printf '%s\n' "$STUB_REPODIGEST" ;;
  create) echo "cid-stub" ;;
  *)      : ;;
esac
exit 0
SH
printf '#!/usr/bin/env bash\nexit 0\n' > "$DSTUB/mkdir"
cp "$DSTUB/mkdir" "$DSTUB/chmod"
chmod +x "$STUB"/* "$DSTUB"/*

# ---- resolve-tested-image.sh -------------------------------------------
LOGS="$T/logs"; mkdir -p "$LOGS"
RUNS="$T/runs.json"; : > "$T/view.log"

run_resolve() {  # $1: runs.json path
  STUB_RUNS_JSON="$1" STUB_LOG_DIR="$LOGS" STUB_VIEW_LOG="$T/view.log" GH_TOKEN=fake \
    PATH="$STUB:$PATH" deploy/ci/resolve-tested-image.sh "$REPO" "$COMMIT"
}

marker_line() { # $1: step name, $2: ref
  printf 'pilot\t%s\t2026-10-27T03:00:00.0000000Z TESTED_GATE_IMAGE=%s\n' "$1" "$2"
}

run_record() { # $1: id, $2: attempt, $3: conclusion, $4: repo full_name, $5: head_sha, $6: path, $7: event
  jq -nc --argjson id "$1" --argjson attempt "$2" --arg conclusion "$3" \
    --arg repo "$4" --arg sha "$5" --arg path "$6" --arg event "$7" \
    '{id:$id, run_attempt:$attempt, conclusion:$conclusion,
      head_repository:{full_name:$repo}, head_sha:$sha, path:$path, event:$event,
      head_branch:"main"}'
}

VALID=$(run_record 4242 2 success "$REPO" "$COMMIT" ".github/workflows/integration.yml" workflow_dispatch)
printf '{"workflow_runs":[%s,%s]}\n' "$VALID" "$(run_record 4100 1 failure "$REPO" "$COMMIT" ".github/workflows/integration.yml" workflow_dispatch)" > "$RUNS"
marker_line "Record the tested gate image digest" "$REF" > "$LOGS/4242.log"
: > "$T/view.log"
out=$(run_resolve "$RUNS" 2>/dev/null); rc=$?
[ $rc -eq 0 ] && [ "$out" = "$REF" ] && grep -q "view 4242 attempt=2" "$T/view.log" \
  && ok "resolve: green run yields its tested digest, logs pinned to the listed attempt" \
  || bad "resolve: green run (rc=$rc out=$out; $(cat "$T/view.log"))"

marker_line "Some other step" "$REF" > "$LOGS/4242.log"
out=$(run_resolve "$RUNS" 2>/dev/null); rc=$?
[ $rc -eq 1 ] && ok "resolve: marker text outside the dedicated step is ignored" \
  || bad "resolve: wrong-step marker (rc=$rc)"
marker_line "Record the tested gate image digest" "$REF" > "$LOGS/4242.log"

# forged/off-repo/off-workflow/off-sha/off-event records are all filtered,
# even though the endpoint query already asked for this sha and workflow
for field in repo sha path event; do
  case "$field" in
    repo)  rec=$(run_record 4600 1 success "attacker/the-membrane" "$COMMIT" ".github/workflows/integration.yml" workflow_dispatch) ;;
    sha)   rec=$(run_record 4600 1 success "$REPO" "ffffffffffffffffffffffffffffffffffffffff" ".github/workflows/integration.yml" workflow_dispatch) ;;
    path)  rec=$(run_record 4600 1 success "$REPO" "$COMMIT" ".github/workflows/evil.yml" workflow_dispatch) ;;
    event) rec=$(run_record 4600 1 success "$REPO" "$COMMIT" ".github/workflows/integration.yml" pull_request) ;;
  esac
  printf '{"workflow_runs":[%s]}\n' "$rec" > "$T/forged.json"
  marker_line "Record the tested gate image digest" "$REF" > "$LOGS/4600.log"
  out=$(run_resolve "$T/forged.json" 2>"$T/err"); rc=$?
  [ $rc -eq 1 ] && grep -q "no valid pilot integration runs" "$T/err" \
    && ok "resolve: forged record (wrong $field) is filtered" \
    || bad "resolve: forged $field (rc=$rc)"
done

# newest run failed: fail closed even with an older green marker run
NEWEST_FAILED=$(run_record 4700 1 failure "$REPO" "$COMMIT" ".github/workflows/integration.yml" workflow_dispatch)
printf '{"workflow_runs":[%s,%s]}\n' "$NEWEST_FAILED" "$VALID" > "$T/failedfirst.json"
out=$(run_resolve "$T/failedfirst.json" 2>"$T/err"); rc=$?
[ $rc -eq 1 ] && grep -q "concluded 'failure', not success" "$T/err" \
  && ok "resolve: newest run failed -> fail closed, no fallback" \
  || bad "resolve: newest failed (rc=$rc)"

# logs unreadable for the newest green run: fail closed, do not skip
NOREAD=$(run_record 9999 1 success "$REPO" "$COMMIT" ".github/workflows/integration.yml" workflow_dispatch)
printf '{"workflow_runs":[%s,%s]}\n' "$NOREAD" "$VALID" > "$T/noread.json"
out=$(run_resolve "$T/noread.json" 2>"$T/err"); rc=$?
[ $rc -eq 1 ] && grep -q "could not read logs" "$T/err" \
  && ok "resolve: unreadable logs for a green run fail closed" \
  || bad "resolve: log fetch failure (rc=$rc)"

echo '{"workflow_runs":[]}' > "$T/empty.json"
out=$(run_resolve "$T/empty.json" 2>"$T/err"); rc=$?
[ $rc -eq 1 ] && grep -q "no valid pilot integration runs" "$T/err" \
  && ok "resolve: failed run (no green record) is refused" \
  || bad "resolve: failed run (rc=$rc)"

cat > "$LOGS/4300.log" <<'SH'
pilot	Write, sign, and verify the run manifest	2026-10-27T03:00:00.0000000Z collected manifest: ok
SH
NOMARKER=$(run_record 4300 1 success "$REPO" "$COMMIT" ".github/workflows/integration.yml" workflow_dispatch)
printf '{"workflow_runs":[%s]}\n' "$NOMARKER" > "$T/nomarker.json"
out=$(run_resolve "$T/nomarker.json" 2>"$T/err"); rc=$?
[ $rc -eq 1 ] && grep -q "publish=false" "$T/err" \
  && ok "resolve: green run without publish marker is refused" \
  || bad "resolve: no-marker run (rc=$rc)"

printf '{"workflow_runs":[%s,%s]}\n' "$NOMARKER" "$VALID" > "$T/stale.json"
out=$(run_resolve "$T/stale.json" 2>/dev/null); rc=$?
[ $rc -eq 0 ] && [ "$out" = "$REF" ] \
  && ok "resolve: newest green run without marker falls back to latest tested digest" \
  || bad "resolve: stale fallback (rc=$rc out=$out)"

marker_line "Record the tested gate image digest" "ghcr.io/$REPO/membrane-gate:edge" > "$LOGS/4400.log"
MUT=$(run_record 4400 1 success "$REPO" "$COMMIT" ".github/workflows/integration.yml" workflow_dispatch)
printf '{"workflow_runs":[%s]}\n' "$MUT" > "$T/mutable.json"
out=$(run_resolve "$T/mutable.json" 2>/dev/null); rc=$?
[ $rc -eq 1 ] && ok "resolve: non-digest (mutable tag) marker is refused" \
  || bad "resolve: mutable marker (rc=$rc)"

marker_line "Record the tested gate image digest" "ghcr.io/attacker/other@sha256:$DIGEST" > "$LOGS/4500.log"
OTH=$(run_record 4500 1 success "$REPO" "$COMMIT" ".github/workflows/integration.yml" workflow_dispatch)
printf '{"workflow_runs":[%s]}\n' "$OTH" > "$T/otherrepo.json"
out=$(run_resolve "$T/otherrepo.json" 2>/dev/null); rc=$?
[ $rc -eq 1 ] && ok "resolve: marker for another repository's image is refused" \
  || bad "resolve: other-repo marker (rc=$rc)"

marker_line "Record the tested gate image digest" "$REF2" > "$LOGS/4300.log"
out=$(run_resolve "$T/stale.json" 2>/dev/null); rc=$?
[ $rc -eq 0 ] && [ "$out" = "$REF2" ] && ok "resolve: newest green run with marker wins" \
  || bad "resolve: newest-first (rc=$rc out=$out)"

# ---- release-tags.sh ----------------------------------------------------
out=$(deploy/ci/release-tags.sh push v1.2.3)
[ "$out" = "1.2.3 1.2" ] && ok "tags: v1.2.3 -> '1.2.3 1.2'" || bad "tags: v1.2.3 ($out)"
out=$(deploy/ci/release-tags.sh push v1.2)
[ "$out" = "1.2" ] && ok "tags: v1.2 -> '1.2' (no bogus major tag)" || bad "tags: v1.2 ($out)"
out=$(deploy/ci/release-tags.sh workflow_dispatch main)
[ "$out" = "edge" ] && ok "tags: dispatch -> edge" || bad "tags: dispatch ($out)"

# ---- promote-tested-image.sh --------------------------------------------
MANIFEST='{"schemaVersion":2,"mediaType":"application/vnd.docker.distribution.manifest.v2+json","config":{"digest":"sha256:0000"}}'
P_DIGEST=$(printf '%s' "$MANIFEST" | sha256sum | cut -d' ' -f1)
P_REF="ghcr.io/$REPO/membrane-gate@sha256:$P_DIGEST"
PUT_LOG="$T/put.log"

run_promote() { # $1: source GET bytes, $2: tag GET bytes, rest: promote args
  local src="$1" tag="$2"; shift 2
  env PATH="$STUB:$PATH" GHCR_USER=u GHCR_TOKEN=t \
      STUB_PUT_LOG="$PUT_LOG" STUB_GET_SRC_BYTES="$src" STUB_GET_TAG_BYTES="$tag" \
      deploy/ci/promote-tested-image.sh "$@"
}

: > "$PUT_LOG"
out=$(run_promote "$MANIFEST" "$MANIFEST" "$REPO" membrane-gate "$P_REF" 1.2.3 1.2 2>&1); rc=$?
if [ $rc -eq 0 ] && grep -q "PUT 1.2.3 $P_DIGEST" "$PUT_LOG" && grep -q "PUT 1.2 $P_DIGEST" "$PUT_LOG"; then
  ok "promote: byte-exact manifest copied to both release tags"
else
  bad "promote: happy path (rc=$rc)"; printf '%s\n' "$out" | tail -3
fi

: > "$PUT_LOG"
out=$(run_promote "tampered bytes" "$MANIFEST" "$REPO" membrane-gate "$P_REF" 1.2.3 2>&1); rc=$?
[ $rc -eq 1 ] && [ ! -s "$PUT_LOG" ] && printf '%s' "$out" | grep -q "Refusing to tag" \
  && ok "promote: source-bytes mismatch refused before any tag write" \
  || bad "promote: source mismatch (rc=$rc)"

: > "$PUT_LOG"
out=$(run_promote "$MANIFEST" "swapped bytes" "$REPO" membrane-gate "$P_REF" 1.2.3 2>&1); rc=$?
[ $rc -eq 1 ] && printf '%s' "$out" | grep -q "does not resolve\|not the tested" \
  && ok "promote: post-write re-read mismatch fails the release" \
  || bad "promote: post-PUT mismatch (rc=$rc)"

out=$(run_promote "$MANIFEST" "$MANIFEST" "$REPO" membrane-gate "ghcr.io/$REPO/membrane-gate:edge" edge 2>&1); rc=$?
[ $rc -eq 1 ] && ok "promote: non-digest source ref is refused" || bad "promote: non-digest src (rc=$rc)"

out=$(run_promote "$MANIFEST" "$MANIFEST" "$REPO" membrane-gate "ghcr.io/attacker/other@sha256:$P_DIGEST" edge 2>&1); rc=$?
[ $rc -eq 1 ] && ok "promote: source ref from another repo is refused" || bad "promote: other-repo src (rc=$rc)"

: > "$PUT_LOG"
out=$(env STUB_CTYPE="application/vnd.oci.image.index.v1+json" PATH="$STUB:$PATH" GHCR_USER=u GHCR_TOKEN=t \
      STUB_PUT_LOG="$PUT_LOG" STUB_GET_SRC_BYTES="$MANIFEST" STUB_GET_TAG_BYTES="$MANIFEST" \
      deploy/ci/promote-tested-image.sh "$REPO" membrane-gate "$P_REF" edge 2>&1); rc=$?
[ $rc -eq 1 ] && [ ! -s "$PUT_LOG" ] && printf '%s' "$out" | grep -q "single image manifest" \
  && ok "promote: index/manifest-list media type is refused before tagging" \
  || bad "promote: index media type (rc=$rc)"

# ---- deploy/gate/deploy.sh ----------------------------------------------
REMOTE="$T/remote"; mkdir -p "$REMOTE"; : > "$REMOTE/.env"

run_deploy() {  # $1: stubbed RepoDigests answer; $2: MEMBRANE_GATE_IMAGE or UNSET; rest: deploy.sh args
  local repodigest="$1" image="$2"; shift 2
  local -a envs=(PATH="$STUB:$PATH" MEMBRANE_REMOTE_DIR="$REMOTE"
    DOCKER_STUB="$DSTUB" STUB_REPODIGEST="$repodigest")
  [ "$image" != UNSET ] && envs+=(MEMBRANE_GATE_IMAGE="$image")
  env "${envs[@]}" bash deploy/gate/deploy.sh "$@"
}

out=$(run_deploy "$REF" UNSET 2>&1); rc=$?
[ $rc -eq 1 ] && printf '%s' "$out" | grep -q "signed run manifest" \
  && ok "deploy: missing MEMBRANE_GATE_IMAGE is refused with guidance" \
  || bad "deploy: missing ref (rc=$rc)"

out=$(run_deploy "$REF" "ghcr.io/$REPO/membrane-gate:edge" 2>&1); rc=$?
[ $rc -eq 1 ] && printf '%s' "$out" | grep -q "digest-pinned" \
  && ok "deploy: mutable tag ref is refused" \
  || bad "deploy: mutable tag (rc=$rc)"

out=$(run_deploy "$REF" "$REF" 2>&1); rc=$?
if [ $rc -eq 0 ] && grep -qF "MEMBRANE_GATE_IMAGE='$REF'" "$REMOTE/remote-invocation.sh"; then
  ok "deploy: digest ref deploys and is exported to the host"
else
  bad "deploy: digest success path (rc=$rc)"
  printf '%s\n' "$out" | tail -5
fi

out=$(run_deploy "$OTHER_REF" "$REF" 2>&1); rc=$?
[ $rc -eq 1 ] && printf '%s' "$out" | grep -q "digest mismatch" \
  && ok "deploy: post-pull digest mismatch aborts" \
  || bad "deploy: mismatch (rc=$rc)"

out=$(run_deploy "$REF" UNSET --build-local 2>&1); rc=$?
[ $rc -eq 0 ] && grep -q "docker build -f Dockerfile -t membrane-gate:local" "$REMOTE/remote-invocation.sh" \
  && ok "deploy: --build-local keeps the source-build path" \
  || bad "deploy: build-local (rc=$rc)"

echo
echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]

# Optional source-run JSON must preserve existing selection semantics.
marker_line "Record the tested gate image digest" "$REF" > "$LOGS/4242.log"
printf '{"workflow_runs":[%s]}\n' "$VALID" > "$RUNS"
json_out=$(STUB_RUNS_JSON="$RUNS" STUB_LOG_DIR="$LOGS" STUB_VIEW_LOG="$T/view.log" GH_TOKEN=fake PATH="$STUB:$PATH" deploy/ci/resolve-tested-image.sh "$REPO" "$COMMIT" --provenance-json)
jq -e --arg ref "$REF" --arg sha "$COMMIT" '.ref == $ref and .commit == $sha and .run_id == "4242" and .run_attempt == "2" and .run_url == "https://github.com/membrane-hq/the-membrane/actions/runs/4242"' <<<"$json_out" >/dev/null || exit 1
echo "1 source-run JSON fixture passed"
