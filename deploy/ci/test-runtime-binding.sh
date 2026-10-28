#!/usr/bin/env bash
# Stub checks only. Not evidence of a running container.
set -euo pipefail
cd "$(dirname "$0")/../.."
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
mkdir "$T/bin"
cat > "$T/bin/docker" <<'SH'
#!/usr/bin/env bash
case "$1 $2" in
 'image inspect') printf '%s' "$IMAGE" ;;
 'container inspect') cat "$INSPECT" ;;
 *) exit 9 ;;
esac
SH
chmod +x "$T/bin/docker"
export PATH="$T/bin:$PATH" IMAGE="sha256:$(printf 'a%.0s' {1..64})" INSPECT="$T/inspect.json"
REF="ghcr.io/membrane-hq/the-membrane/membrane-gate@$IMAGE"
CID=$(printf 'b%.0s' {1..64})
jq -n --arg image "$IMAGE" --arg ref "$REF" '[{Image:$image,Config:{Image:$ref},RestartCount:0,State:{Running:true,Pid:123},NetworkSettings:{Ports:{"8787/tcp":[{HostIp:"127.0.0.1",HostPort:"8787"}]}}}]' > "$T/good"
cp "$T/good" "$INSPECT"
deploy/ci/verify-pulled-gate.sh "$REF" "$CID" >/dev/null
echo 'ok - expected running image and loopback endpoint'
for expr in '.[0].Image="sha256:wrong"' '.[0].Config.Image="mutable:tag"' '.[0].State.Running=false' '.[0].State.Pid=0' '.[0].RestartCount=1' '.[0].NetworkSettings.Ports["8787/tcp"][0].HostIp="0.0.0.0"' '.[0].NetworkSettings.Ports["8787/tcp"][0].HostPort="9999"' '.=[]'; do
 jq "$expr" "$T/good" > "$INSPECT"
 if deploy/ci/verify-pulled-gate.sh "$REF" "$CID" >/dev/null 2>&1; then echo "FAIL $expr"; exit 1; fi
 echo "ok - rejected $expr"
done
if deploy/ci/verify-pulled-gate.sh "$REF" "$CID $CID" >/dev/null 2>&1; then exit 1; fi
echo '10 runtime-binding fixture checks passed (not a live container check)'
