# Daily OTS rollup (relay-2)

Systemd timer runs `membrane rollup daily` at **00:15 UTC**:

1. Export yesterday's `RollupBundle` from the attestation bus
2. Sign with `NOSTR_NSEC`
3. Stamp via OpenTimestamps and publish `membrane.anchor.ots`

## Install

```bash
# 1. Install the gate (its binary excludes OTS)
./deploy/gate/deploy.sh

# 2. Build the separate OTS binary and install timer (reuses deploy/gate/.env)
chmod +x deploy/rollup/install.sh
./deploy/rollup/install.sh
```

## Manual run

```bash
ssh relay-2 'systemctl start membrane-rollup.service'
ssh relay-2 'journalctl -u membrane-rollup.service -n 30 --no-pager'
```

Artifacts land in `/var/lib/membrane/rollup/rollup-YYYY-MM-DD.*`

The installer builds `membrane-cli` with `--no-default-features --features ots` using `deploy/rollup/Dockerfile` and installs `/opt/membrane/rollup/membrane`. The gate binary remains unchanged; the rollup binary does not include the demo.
