# Nostr Ghost Cloudflare App

This is the stateless browser-only runtime for the Nostr/CodiMD/Ghost direction.

The important runtime rule is: there is no Ghost server, no CodiMD server, and no local or hosted database. Cloudflare Pages serves static files only. The browser derives the Nostr key from a passkey PRF, stores private notes as an encrypted replaceable Nostr vault, and publishes public blog posts as Nostr long-form events.

## Model

- Private workspace: encrypted vault event, `kind 30078`, `d=nostr-ghost-vault`.
- Public blog: Casper theme structure and CSS rendering public long-form Nostr events, `kind 30023`.
- Private editor: CodiMD-shaped editor shell with edit/both/view modes, backed only by the encrypted Nostr vault.
- Backup: the encrypted vault contains all notes, including public note source.
- Identity: passkey PRF derives the same deterministic Nostr key material used by the CodiMD MVP.
- Deployment: Cloudflare Pages static output from `apps/nostr-ghost/public`.

## Cloudflare Pages

Use these settings:

- Project root: `apps/nostr-ghost`
- Build command: none
- Build output directory: `public`

For Wrangler-based deployment:

```sh
cd apps/nostr-ghost
wrangler pages deploy public
```

## Local Smoke Test

```sh
npm run test:nostr-ghost
```

The app intentionally stores only passkey credential id and relay preferences in browser storage. Notes are restored from Nostr after login.

## Theme Sources

- `public/casper-screen.css` is copied from `TryGhost/Casper` and is covered by `CASPER-LICENSE`.
- `public/fork-awesome` is copied from `fork-awesome` and is covered by `FORK-AWESOME-LICENSES`.
- The editor shell intentionally mirrors CodiMD's familiar navbar, mode buttons, edit pane, and preview pane, without server-only collaboration or database features.
