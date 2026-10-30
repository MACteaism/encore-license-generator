# encore-license-generator

Standalone tool for issuing device-bound `.enclib` licenses for Encore.
Split out of the Encore-Android repository so the signing machinery can live
on its own machine/folder, away from the app source.

The app ships only an ECDSA **public** key. Licenses are signed offline with a
private key that stays on this machine. Each license contains the pack
passphrase encrypted to one device's non-exportable Android Keystore RSA key,
so a license cannot be copied to another device.

> This is access control for a small public test, not DRM. See
> `tools/ENCLIB_LICENSE.md` for the full security notes.

## Layout

```
api/
  index.py               Vercel serverless function (Flask): hosted generator
packs.json               Public pack metadata (pack IDs, song counts, sizes)
tools/
  enclib_license.py      CLI engine (keygen / issue / inspect / selftest)
  main.py                Local-only web UI (thin wrapper around the CLI)
  ENCLIB_LICENSE.md      Full manual: setup, issuing, revocation, security
  keys/                  Signing private key (git-ignored, never committed)
```

## Setup

1. Generate a signing key (once):

   ```
   python tools/enclib_license.py keygen
   ```

   The key is written to `tools/keys/enclib-license-signing-key.pem`.
   Back it up somewhere safe; losing it means every issued license must be
   re-signed with a new key and a new app build.

2. Put `.enclib` packs and passphrase-only `.txt` files in `test-output/`
   (or point `--pack-dir` / `--passphrase-dir` elsewhere).

## Hosted generator (Vercel)

`api/index.py` serves the same license UI at
https://encore-license-generator.vercel.app, so testers can be issued licenses
without access to this machine. The private key, passphrases, and admin token
live only in Vercel's encrypted environment variables:

| Variable | Purpose |
|---|---|
| `ENCLIB_SIGNING_KEY` | PEM text of the signing private key |
| `ENCLIB_ADMIN_TOKEN` | Gates `POST /api/issue` (constant-time compared) |
| `ENCLIB_PASSPHRASE_<NAME>` | One per passphrase listed in `packs.json` |

`packs.json` carries only public metadata read from the `.enclib` headers
(pack ID, song count, size); the function fabricates an 80-byte header stub
per request, so real pack binaries never touch the server. Deploy with
`npx vercel --prod`; `.vercelignore` keeps keys and local test data out of
deployments. Verified end-to-end against a real device (activation code ->
serverless signing -> Android Keystore unwrap, 2026-10-30).

To rotate the admin token: `npx vercel env add ENCLIB_ADMIN_TOKEN production`,
then redeploy — no code changes.

## Issue a license (web UI, local)

```
python tools/main.py
```

Opens `http://127.0.0.1:8765` in your browser. Binds to localhost only; the
signing key and passphrases never leave this computer. Do not put it behind a
public reverse proxy.

## Issue a license (CLI)

```
python tools/enclib_license.py issue --activation ENCLIB-ACT-1:... --pack test-output\Encore-Library.enclib --days 14
```

## Verify the tooling

```
python tools/enclib_license.py selftest
```

Requires Python 3.10+ (uses `datetime.UTC`). No third-party dependencies for
the CLI and local UI; the hosted function needs Flask + cryptography (see
`requirements.txt`).
