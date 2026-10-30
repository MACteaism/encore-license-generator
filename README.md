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
tools/
  enclib_license.py      CLI engine (keygen / issue / inspect / selftest)
  enclib_license_web.py  Local-only web UI (thin wrapper around the CLI)
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

## Issue a license (web UI)

```
python tools/enclib_license_web.py
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

Requires Python 3.10+ (uses `datetime.UTC`). No third-party dependencies.
