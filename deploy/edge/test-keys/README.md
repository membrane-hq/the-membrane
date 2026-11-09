# Disposable edge test key

`edge-test-key.pem` and `jwks.json` are a generated RSA-2048 pair used ONLY
by the local required-path reference deployment (`../docker-compose.yml`)
and its `../verify.sh` check. The private key is checked in deliberately so
the reference deployment and CI can mint assertions; it signs nothing of
value and must never be trusted by any real deployment. A production edge
uses the operator's own edge identity issuer and keys; see
`../../../docs/edge-deployment.md`.
