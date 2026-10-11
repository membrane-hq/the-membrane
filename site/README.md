# The Membrane landing site

Static public marketing page for **The Membrane** - a fail-closed authorization gateway for AI agents with production write access.

Copy source of truth: [`docs/product.md`](../docs/product.md).

This site presents the software and links to its demo. It does not expose
production controls. The demo demonstrates gate checks and receipt chaining with
simulated tool effects; the operator dashboard and gate run separately in the
operator's environment.

## Preview locally

```bash
# from repo root
python3 -m http.server 8080 --directory site
# open http://127.0.0.1:8080/
```

Or any static file server pointed at `site/`.

## Structure

```text
site/
  index.html      landing page
  terms/          Terms of Service
  privacy/        Privacy Policy
  styles.css      layout + motion
  app.js          gate canvas + scroll reveals
  assets/         favicon + OG image
  README.md       this file
```

## Live

| | |
|---|---|
| Custom domain | https://membrane.dojopop.live |
| Pages default | https://membrane-landing.pages.dev |
| CF Pages project | `membrane-landing` |
| Legacy hostname | `attestable.dojopop.live` should redirect here (or be removed) |

## Deploy (Cloudflare Pages)

### Option A - Wrangler (already provisioned)

```bash
# from repo root; requires CLOUDFLARE_API_TOKEN + account access
doppler run --project dojopop --config prd_zorie -- bash -c '
  export CLOUDFLARE_API_TOKEN
  export CLOUDFLARE_ACCOUNT_ID=dfc6e38d5b254f0f8ffac8a0e554112a
  wrangler pages deploy site --project-name membrane-landing --branch main
'
```

Custom domain `membrane.dojopop.live` is a proxied CNAME → `membrane-landing.pages.dev` on the `dojopop.live` zone.

Legacy `attestable.dojopop.live` still points at the old Pages project `attestable` (currently redeployed with The Membrane branding). Prefer a Cloudflare redirect rule to `https://membrane.dojopop.live` when a token with Rules Write is available; otherwise remove the legacy custom domain + DNS CNAME.

### Option B - Git-connected Pages

1. Cloudflare Dashboard → Workers & Pages → Create → Pages → Connect to Git
2. Select `Z0rlord/the-membrane`
3. Build settings:
   - Framework preset: None
   - Build command: *(empty)*
   - Build output directory: `site`
4. Add custom domain `membrane.dojopop.live`

### Option C - Tunnel / existing CF ingress

If Pages is unavailable, serve `site/` from any static host behind the existing
`dojopop.live` Cloudflare tunnel and point `membrane.dojopop.live` at that origin.
See `deploy/grasp/update-tunnel-ingress.sh` for the tunnel pattern used elsewhere.

## What is intentionally not here

| Deferred | Why |
|----------|-----|
| Production controls | The public demo is separate from the operator deployment |
