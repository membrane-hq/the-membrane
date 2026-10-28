#!/usr/bin/env bash
# Fixture tests only. Docker is stubbed; this is not a container run.
set -euo pipefail
cd "$(dirname "$0")/../.."
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
mkdir "$T/bin"
cat > "$T/bin/docker" <<'SH'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$CALLS"
case "$1 $2" in
  'info '*) exit 0 ;;
  'image inspect')
    if [ $# = 3 ]; then [ -n "${CACHED:-}" ]; else printf '%s' "$INSPECT"; fi ;;
  'pull '*) [ "${PULL_FAIL:-0}" = 0 ] ;;

  *) exit 9 ;;
esac
SH
chmod +x "$T/bin/docker"
export PATH="$T/bin:$PATH" CALLS="$T/calls"
REPO=membrane-hq/the-membrane
REF="ghcr.io/$REPO/membrane-gate@sha256:$(printf 'a%.0s' {1..64})"
export INSPECT="[\"$REF\"]"
PASS=0
check() {
  name="$1"; expected="$2"; shift 2
  : > "$CALLS"
  if "$@" >"$T/out" 2>"$T/err"; then code=0; else code=1; fi
  [ "$code" = "$expected" ] || { echo "FAIL: $name"; cat "$T/err"; exit 1; }
  PASS=$((PASS+1)); echo "ok - $name"
}
run() { deploy/ci/pull-tested-image.sh "$REPO" "$1"; }
check 'fresh pull with exact registry digest' 0 run "$REF"
grep -q '^pull ' "$CALLS"
check 'mutable tag rejected before Docker' 1 run "ghcr.io/$REPO/membrane-gate:edge"
[ ! -s "$CALLS" ]
check 'wrong repository rejected' 1 run "${REF/membrane-hq/other}"
[ ! -s "$CALLS" ]
check 'truncated digest rejected' 1 run "${REF%a}"
check 'extra characters rejected' 1 run "${REF}x"
export CACHED=sha256:existing
check 'cached target digest fails without pull or removal' 1 run "$REF"
[ "$(grep -c '^pull ' "$CALLS" || true)" = 0 ]
unset CACHED
export PULL_FAIL=1
check 'pull failure stops before inspect' 1 run "$REF"
! grep -q 'image inspect .* --format' "$CALLS"
unset PULL_FAIL
export INSPECT='[]'
check 'missing expected digest rejected' 1 run "$REF"
export INSPECT='null'
check 'null digest list rejected' 1 run "$REF"
export INSPECT='not json'
check 'malformed inspect rejected' 1 run "$REF"
export INSPECT='["ghcr.io/other/repo@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]'
check 'wrong registry digest rejected' 1 run "$REF"
echo "$PASS cold-install fixture checks passed (not an actual cold install)"
