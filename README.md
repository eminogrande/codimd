# Nostr Hugo

Nostr Hugo is a stateless browser app for private markdown writing and public Nostr publishing.

There is no application server, no hosted database, and no local install for users. Cloudflare Pages serves static files. The browser derives Nostr key material from a passkey PRF, stores private notes as an encrypted Nostr vault, and publishes public posts as Nostr long-form events.

## Features

- Passkey PRF unlock for deterministic Nostr identity.
- Private markdown studio locked until passkey unlock.
- Encrypted autosave and backup to Nostr relays.
- Public blog publishing with Nostr long-form events.
- Public profile metadata for blog name, description, and avatar.
- Personal blog routes at `/<nostr-pubkey-hex>`.
- Single post routes at `/<nostr-pubkey-hex>/<post-slug>`.
- Cloudflare Pages deployment with static files only.

## Runtime Model

- Private workspace: encrypted replaceable event, `kind 30078`, `d=nostr-hugo-vault`.
- Public posts: Nostr long-form content, `kind 30023`.
- Public profile: Nostr metadata, `kind 0`.
- Browser storage: passkey credential id and relay preferences only.
- Source of truth: Nostr relays.

## Routes

- `/` landing page and public-key loader.
- `/<nostr-pubkey-hex>` personal public blog.
- `/<nostr-pubkey-hex>/<post-slug>` single public post.
- `/studio` private markdown studio.

## Local

```sh
npm test
```

To serve the app locally, serve `apps/nostr-hugo/public` with SPA fallback to `index.html`.

## Cloudflare Pages

- Project root: `apps/nostr-hugo`
- Build command: none
- Build output directory: `public`

`apps/nostr-hugo/public/_redirects` keeps direct blog and post URLs working on Cloudflare Pages.
