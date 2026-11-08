#!/usr/bin/env bash
# Mint an RS256 edge assertion for the local required-path reference
# deployment. Uses the checked-in disposable test key by default; a real
# deployment's edge identity layer issues these, never this script.
set -euo pipefail
if [ $# -lt 4 ]; then
  echo "usage: mint-assertion.sh KEY.pem ISSUER AUDIENCE SUBJECT [TTL_SECS] [KID]" >&2
  exit 2
fi
key=$1 issuer=$2 audience=$3 subject=$4 ttl=${5:-300} kid=${6:-edge-test}
b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }
header=$(printf '{"alg":"RS256","kid":"%s","typ":"JWT"}' "$kid" | b64url)
now=$(date +%s)
payload=$(printf '{"iss":"%s","aud":"%s","sub":"%s","exp":%d,"nbf":%d}' \
  "$issuer" "$audience" "$subject" "$((now + ttl))" "$((now - 1))" | b64url)
sig=$(printf '%s.%s' "$header" "$payload" | openssl dgst -sha256 -sign "$key" -binary | b64url)
printf '%s.%s.%s\n' "$header" "$payload" "$sig"
