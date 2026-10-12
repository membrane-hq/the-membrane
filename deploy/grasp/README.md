# Membrane GRASP backup (relay-2)

Self-hosted [GRASP](https://ngit.dev/grasp/) instance for **the-membrane** git backup on gitworkshop.dev / Nostr.

| | |
|---|---|
| Tailnet | `ws://relay-2:7334` · `http://relay-2:7334` |
| Public | `wss://membrane-grasp.dojopop.live` (after tunnel + DNS) |
| Remote path | `/opt/membrane/grasp` |
| Deploy | `./deploy/grasp/deploy.sh` |

## Identity keys (do not mix)

| Doppler secret | Role | Pubkey (hex) |
|---|---|---|
| `NOSTR_NSEC` | Membrane attestation bus, gate, rollup signer | `b3d8544ddd5896f75ef66c210f5c0d6ded9f7925163ebcbc89e678bdc1e48c6a` |
| `NGIT_NSEC` | ngit.dev / gitworkshop maintainer (`ngit init`, Grasp pushes) | `6b497b5b4e29623c6166c3f114cfb8344c01a536a45af84fdd4c5072d2083bd2` (`npub1ddyhkk6w993rcctxc0c3fnacx3xqrffk53d0sn7af3g895sg80fqa9hza9`) |

- **Never** use `NGIT_NSEC` for membrane gate or relay deploys.
- **Never** commit nsec values; inject via Doppler or remote `.env` (chmod 600).

## Deploy grasp server

```bash
doppler run --project dojopop --config prd_zorie -- bash -c '
  printf "NGIT_RELAY_OWNER_NSEC=%s\n" "$NGIT_NSEC" > deploy/grasp/.env
  cat deploy/grasp/env.example >> deploy/grasp/.env
'
./deploy/grasp/deploy.sh relay-2
./deploy/grasp/update-tunnel-ingress.sh   # public HTTPS/WSS via Cloudflare
```

`NGIT_RELAY_OWNER_NSEC` on the server should be the **ngit maintainer** key (`NGIT_NSEC`), not the membrane operator.

`env.example` values with spaces must stay quoted (e.g. `NGIT_RELAY_NAME="Membrane GRASP"`).

## Publish / back up the-membrane

One-time init (already done for this repo):

```bash
cd /path/to/the-membrane
export PATH="$HOME/.cargo/bin:$HOME/.local/bin:$PATH"

doppler run --project dojopop --config prd_zorie -- bash -c '
  ngit -n "$NGIT_NSEC" init \
    --identifier the-membrane \
    --grasp-server membrane-grasp.dojopop.live \
    --grasp-server gitworkshop.dev
  git remote rename origin grasp 2>/dev/null || true
  git remote add github https://github.com/membrane-hq/the-membrane.git 2>/dev/null || true
'
```

## Multi-relay backup

Repository identifier: **`the-membrane`** (not `docs/whitepaper` — that path is unrelated).

**Grasp servers** on the announcement (redundant git mirrors):

| Server | Role |
|--------|------|
| `membrane-grasp.dojopop.live` | Self-hosted (relay-2) |
| `relay.ngit.dev` | Public ngit-grasp |
| `gitnostr.com` | Public ngit-grasp |
| `gitworkshop.dev` | Listed for gitworkshop ecosystem / discovery (web UI; git data served by the other instances) |

**Nostr relays** (announcement propagation beyond grasp): `wss://relay.damus.io`, `wss://nos.lol`, `wss://relay.ditto.pub`.

Update grasp list (always wrap in `bash -c` so Doppler injects `NGIT_NSEC`):

```bash
doppler run --project dojopop --config prd_zorie -- bash -c '
  export PATH="$HOME/.cargo/bin:$HOME/.local/bin:$PATH"
  ngit -n "$NGIT_NSEC" -d -f repo edit --clean \
    -g membrane-grasp.dojopop.live \
    -g gitworkshop.dev \
    -g relay.ngit.dev \
    -g gitnostr.com \
    --relay wss://relay.damus.io \
    --relay wss://nos.lol \
    --relay wss://relay.ditto.pub \
    --web "https://gitworkshop.dev/npub1ddyhkk6w993rcctxc0c3fnacx3xqrffk53d0sn7af3g895sg80fqa9hza9/gitworkshop.dev/the-membrane"
'
```

**Push backup** (after commits on `main`):

```bash
doppler run --project dojopop --config prd_zorie -- bash -c '
  export PATH="$HOME/.cargo/bin:$HOME/.local/bin:$PATH"
  ngit -n "$NGIT_NSEC" account login --defaults
  git push origin main
  ngit -n "$NGIT_NSEC" -d -f sync -r main
'
```

If sync fails on a stale branch in nostr state (e.g. `cursor/...`), sync only `main` as above or delete orphan `refs/remotes/origin/*` first.

If public DNS for `membrane-grasp.dojopop.live` fails locally, push from relay-2 instead:

```bash
rsync -az --delete -e ssh ./ relay-2:/opt/membrane/grasp/repo-worktree/
ssh relay-2 'eval "$(grep ^NGIT_RELAY_OWNER_NSEC= /opt/membrane/grasp/.env)"; ...'  # see push block above
```

## Clone

| Method | URL |
|--------|-----|
| Nostr | `nostr://npub1ddyhkk6w993rcctxc0c3fnacx3xqrffk53d0sn7af3g895sg80fqa9hza9/membrane-grasp.dojopop.live/the-membrane` |
| HTTPS (public) | `https://membrane-grasp.dojopop.live/npub1ddyhkk6w993rcctxc0c3fnacx3xqrffk53d0sn7af3g895sg80fqa9hza9/the-membrane.git` |
| HTTP (tailnet) | `http://relay-2:7334/npub1ddyhkk6w993rcctxc0c3fnacx3xqrffk53d0sn7af3g895sg80fqa9hza9/the-membrane.git` |
| gitworkshop | [gitworkshop.dev/.../the-membrane](https://gitworkshop.dev/npub1ddyhkk6w993rcctxc0c3fnacx3xqrffk53d0sn7af3g895sg80fqa9hza9/membrane-grasp.dojopop.live/the-membrane) |

```bash
export PATH="$HOME/.cargo/bin:$HOME/.local/bin:$PATH"
git clone nostr://npub1ddyhkk6w993rcctxc0c3fnacx3xqrffk53d0sn7af3g895sg80fqa9hza9/membrane-grasp.dojopop.live/the-membrane
```

## Local ngit identity

Use the **ngit.dev account** key only for `ngit` / Grasp — not for membrane gate or relay:

```bash
export PATH="$HOME/.cargo/bin:$HOME/.local/bin:$PATH"
doppler run --project dojopop --config prd_zorie -- bash -c '
  ngit -n "$NGIT_NSEC" account login --defaults
'
```

## Verify

**Mirror check** (`main` at `3d0dcca` or later):

```bash
NPUB=npub1ddyhkk6w993rcctxc0c3fnacx3xqrffk53d0sn7af3g895sg80fqa9hza9
for host in membrane-grasp.dojopop.live relay.ngit.dev gitnostr.com; do
  echo -n "$host: "
  git ls-remote "https://${host}/${NPUB}/the-membrane.git" HEAD
done
```

| Mirror | git HTTPS | gitworkshop web |
|--------|-----------|-----------------|
| Self-hosted | `https://membrane-grasp.dojopop.live/.../the-membrane.git` | [membrane-grasp path](https://gitworkshop.dev/npub1ddyhkk6w993rcctxc0c3fnacx3xqrffk53d0sn7af3g895sg80fqa9hza9/membrane-grasp.dojopop.live/the-membrane) |
| relay.ngit.dev | `https://relay.ngit.dev/.../the-membrane.git` | [relay.ngit.dev path](https://gitworkshop.dev/npub1ddyhkk6w993rcctxc0c3fnacx3xqrffk53d0sn7af3g895sg80fqa9hza9/relay.ngit.dev/the-membrane) |
| gitnostr.com | `https://gitnostr.com/.../the-membrane.git` | [gitnostr.com path](https://gitworkshop.dev/npub1ddyhkk6w993rcctxc0c3fnacx3xqrffk53d0sn7af3g895sg80fqa9hza9/gitnostr.com/the-membrane) |

**gitworkshop canonical URL** (browse any listed grasp server):

https://gitworkshop.dev/npub1ddyhkk6w993rcctxc0c3fnacx3xqrffk53d0sn7af3g895sg80fqa9hza9/membrane-grasp.dojopop.live/the-membrane

```bash
# Prefer public HTTPS; tailnet HTTP uses the relay-2 host alias when reachable:
curl -s -H 'Accept: application/nostr+json' https://membrane-grasp.dojopop.live/ | python3 -m json.tool
# or: curl -s -H 'Accept: application/nostr+json' http://relay-2:7334/ | python3 -m json.tool
git clone http://relay-2:7334/npub1ddyhkk6w993rcctxc0c3fnacx3xqrffk53d0sn7af3g895sg80fqa9hza9/the-membrane.git /tmp/membrane-test
```

## Troubleshooting

- **State / push mismatch** (`refs/heads/main would be at fe2a32f7 but state declares ce297ee6`): delete `refs/remotes/origin/*` then `ngit repo edit --clean` and push again.
- **Authentication required**: run `ngit -n "$NGIT_NSEC" account login --defaults` before `git push`.
- **Stale co-maintainer announcement**: an early init under the membrane `NOSTR_NSEC` operator (`npub1k0v9gn...`) may still pool into grasp/relay lists. Only use `NGIT_NSEC` (`npub1ddyhkk...`) for `ngit` commands.
- **`relay-2:7334` times out from Mac**: `relay-2` is an SSH alias (`~/.ssh/config`), not public DNS. Prefer public `https://membrane-grasp.dojopop.live`, or ensure the deployed host is reachable on the private network before using `http://relay-2:7334` / `ws://relay-2:7334`.
- **Mac DNS**: if `membrane-grasp.dojopop.live` does not resolve, fix local DNS / hosts for the public hostname, or push over the private network to `relay-2`.
