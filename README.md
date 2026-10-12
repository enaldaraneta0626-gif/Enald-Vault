# Nightvault

Encrypted personal vault. Everything is encrypted in the browser before it is stored or synced.

## Files
- `index.html`: the app
- `sw.js`, `manifest.webmanifest`, `icons/`: let people install it as an app and open it offline
- `netlify/functions/vault.mjs`: sync endpoint at `/api/vault` (stores only encrypted data, in Netlify Blobs, with rate limits)
- `package.json`: the one dependency the sync function needs (`@netlify/blobs`)
- `netlify.toml`: tells Netlify where the function lives and adds strict security headers

## Check that sync is running
Open `https://<your-site>/api/vault?ping=1`. It should show `{"ok":"nightvault"}`.
