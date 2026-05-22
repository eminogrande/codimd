# Nostr Hugo Cloudflare App

This is the stateless browser-only runtime for the Nostr/Hugo direction.

The important runtime rule is: there is no publishing server and no local or hosted database. Cloudflare Pages serves static files only. The browser derives the Nostr key from a passkey PRF, stores private notes as an encrypted replaceable Nostr vault, and publishes public blog posts as Nostr long-form events.

## Model

- Private workspace: encrypted vault event, `kind 30078`, `d=nostr-hugo-vault`.
- Public blog: Hugo-style static blog UI rendering public long-form Nostr events, `kind 30023`.
- Public profile: Nostr metadata event, `kind 0`, used for the blog name, description, and avatar.
- Private editor: browser-only markdown studio with edit/both/view modes, backed only by the encrypted Nostr vault.
- Backup: the encrypted vault contains all notes, including public note source.
- Identity: passkey PRF derives deterministic Nostr key material.
- Deployment: Cloudflare Pages static output from `apps/nostr-hugo/public`.

## Routes

- `/` is the landing page and public-key loader.
- `/<nostr-pubkey-hex>` is an individual public blog.
- `/<nostr-pubkey-hex>/<post-slug>` is the focused single-post view.
- `/studio` is the locked private markdown studio.

## Cloudflare Pages

Use these settings:

- Project root: `apps/nostr-hugo`
- Build command: none
- Build output directory: `public`

For Wrangler-based deployment:

```sh
cd apps/nostr-hugo
wrangler pages deploy public
```

`public/_redirects` keeps direct blog URLs like `/<nostr-pubkey-hex>` and `/<nostr-pubkey-hex>/<post-slug>` working as SPA routes on Cloudflare Pages.

## Local Smoke Test

```sh
npm run test:nostr-hugo
```

The app intentionally stores only passkey credential id and relay preferences in browser storage. Notes are restored from Nostr after login.

## Theme Sources

- `public/styles.css` is a lightweight Hugo-style static blog theme built for this app.
- `public/fork-awesome` is copied from `fork-awesome` and is covered by `FORK-AWESOME-LICENSES`.
- The private editor keeps the familiar split markdown workflow without server-only collaboration or database features.
