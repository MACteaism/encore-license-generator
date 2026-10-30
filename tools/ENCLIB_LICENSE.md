# Encore `.enclib` test licenses

This is the manual, no-server license flow for encrypted Encore packs. It keeps
the pack file unchanged and keeps the full pack passphrase out of the APK.

The app ships only an ECDSA **public** key. Licenses are signed offline with a
private key that stays on the pack owner's machine. Each license contains the
pack passphrase encrypted to one device's non-exportable Android Keystore RSA
key, so the license cannot be copied to another device. Passphrases longer than
the RSA-OAEP limit are split into multiple encrypted chunks; this is transparent
to the tester. Builds before versionCode 10 only understand a single chunk, so
use the current build for packs with long passphrases (including the full pack).

> This is access control for a small public test, not DRM. During playback the
> decrypted pack key exists in the app process. A rooted or instrumented device
> can recover it. Every copy of a given pack uses the same data key, so one
> extracted passphrase exposes all copies. Expiry and the clock guard use the
> device clock; the guard catches a backward jump after the app has seen the
> license, but it is not trusted time. A reboot plus a date after the last-seen
> time can still work, and a rooted device can patch the check. Do not rely on
> this to protect high-value content or as a substitute for distribution
> rights.

## One-time signer setup

The signer key is generated locally and must **not** be committed:

```powershell
python tools/enclib_license.py keygen
```

Default output:

```text
tools/keys/enclib-license-signing-key.pem
```

The command also prints the Java constants for `EnclibLicense.java`:

```java
public static final String ADMIN_PUBLIC_KEY_B64 = "...";
public static final String ADMIN_KEY_ID = "...";
```

The repository currently pins key ID `f72d5004ef82aff2`. If you generate a new
key, add its public key and ID to `EnclibLicense.ADMIN_KEYS` and rebuild the app.

**Back up the private key offline now.** If it is lost, you cannot issue or renew
licenses for the installed app build. If it is stolen, someone else can issue
licenses. Never send it to testers and never put it in the APK.

## Tester steps

1. Install the test APK.
2. Open Library Manager and tap **Device License**.
3. Tap **Copy** and send the activation code (begins with `ENCLIB-ACT-1:`) to the
   pack owner. The code identifies the device only; it contains no pack key.
4. The owner sends back a `.json` license file.
5. In Library Manager, tap **Import Pack**, pick the `.enclib` file, then
   **Use License** and select the license JSON.

The pack is copied into app storage and unlocked. The app stores a Keystore-wrapped
data key in a sidecar next to the pack for normal playback; it does **not** rewrite
the pack header. The imported `.enclib` stays byte-identical to the distributed
file. The app still checks the signed license expiry on every pack open. When the
license expires, the pack locks again.

If the pack is already imported and locked, select it and press **Unlock Pack**,
then **Use License** and pick the license file.

## Owner steps

### 1. Save the activation code

Save the tester's activation code as a text file, for example
`tester-activation.txt`. One line is enough.

### 2. Issue the license

The pack passphrase is read from `ENCLIB_PASSPHRASE`, `--passphrase-file`, or an
interactive prompt. Prefer the file or prompt so it does not remain in shell
history.

The file must contain **only the passphrase**, on one line, with no labels or
instructions. `--passphrase-file` treats the entire file as the key. For this
workspace, use `test-output\full-pack-passphrase-value.txt`; the human-readable
`full-pack-passphrase.txt` document is not a passphrase file.

```powershell
# Read the passphrase from a passphrase-only file (recommended)
python tools/enclib_license.py issue `
  --activation tester-activation.txt `
  --pack test-output\Encore-Library.enclib `
  --days 14 `
  --passphrase-file test-output\full-pack-passphrase-value.txt `
  --out test-output\license-tester.json
```

Use `--expires 2026-12-31` instead of `--days` for a fixed end date. The
activation code itself is device-only and reusable across packs; the resulting
license is bound to one pack ID and one expiry.

### 3. Verify before sending

```powershell
python tools/enclib_license.py inspect --license test-output\license-tester.json
```

Expected output includes `Signature: OK`, the pack ID, the device hash prefix,
and the expiry. The command never prints the passphrase.

### 4. Send only the license file

Send the `.json` license. Do not send the pack passphrase, the signing private
key, or a passphrase-bearing command line.

## Optional local web UI

For convenience, the owner can issue licenses from a browser without retyping
the activation code or passphrase into a command line:

```powershell
python tools/enclib_license_web.py
```

The tool binds only to `127.0.0.1` and opens
`http://127.0.0.1:8765/` in the default browser. It loads the signing key from
`tools/keys/enclib-license-signing-key.pem`, lists the `.enclib` files in
`test-output`, and lists one-line files in `test-output` whose names contain
`passphrase`. Paste the tester's activation code, choose the pack and passphrase
file, choose the validity period, and download or copy the signed JSON license.

The passphrase file contents are read by the local Python process and are never
sent to the browser. The page does not display or log the passphrase. Only the
single-line `full-pack-passphrase-value.txt` is listed; the multi-line
`full-pack-passphrase.txt` instruction document is filtered out.

Useful options:

```powershell
# Do not open a browser automatically
python tools/enclib_license_web.py --no-browser

# Use a different port (0 chooses a free port)
python tools/enclib_license_web.py --port 8877

# Use another pack/passphrase folder or signing key
python tools/enclib_license_web.py `
  --pack-dir test-output `
  --passphrase-dir test-output `
  --key tools\keys\enclib-license-signing-key.pem
```

**Keep this tool local.** It is not designed for public hosting and must not be
put behind a reverse proxy, tunnel, or shared server. Anyone who can reach the
page could issue licenses while the signing key is loaded. The CLI remains the
fallback and the authoritative implementation; the web UI calls the same
license-issuing code.

## Useful commands

```powershell
# Local self-test of the activation, RSA-OAEP and ECDSA formats
python tools/enclib_license.py selftest

# Fixed expiry date
python tools/enclib_license.py issue `
  --activation tester-activation.txt `
  --pack test-output\Encore-Library.enclib `
  --expires 2026-11-30 `
  --passphrase-file test-output\full-pack-passphrase-value.txt `
  --out test-output\license-tester.json
```

## Testing expiry

Issue a license that expires in a few minutes, import it, then wait for the
expiry with the device clock correct. The pack should lock on the next open, and
a newly issued license should unlock it again.

Moving the clock forward past the expiry also makes the pack lock, but that is
not a reliable expiry test. The guard records the highest wall time it has seen;
moving it forward and then back is treated as a rollback and can lock the pack.
Use the passphrase if a clock change put the saved high-water mark in the future.

```powershell
$exp = [DateTimeOffset]::UtcNow.AddMinutes(2).ToUnixTimeSeconds()
python tools/enclib_license.py issue `
  --activation tester-activation.txt `
  --pack test-output\test-10-renamed.enclib `
  --expires $exp `
  --passphrase-file test-output\test-pack-passphrase.txt `
  --out test-output\license-expiry-test.json `
  --force
```

## Expiry and recovery behavior

- The signed `expiresAt` is checked both when importing the license and whenever
  the app opens the pack.
- Editing the license, sidecar, or expiry breaks the signature or is ignored in
  favor of the signed payload.
- Expired license: import a newly issued license.
- Owner recovery: entering the real pack passphrase unlocks the pack and clears
  the test-license binding, leaving it as a normal Keystore-wrapped pack.
- A different device, a reinstall, or a cleared app Keystore requires a new
  activation code and a new license.

### Clock guard (unreleased after v0.2.0-beta.2)

The app stores a last-seen wall time in `files/enclib/clock-guard.bin`, encrypted
with a dedicated Android Keystore key. It also stores `SystemClock.elapsedRealtime()`
and `Settings.Global.BOOT_COUNT`. On the same boot, wall time must keep pace with
the monotonic clock (with about 10 minutes of tolerance). After a reboot, the
wall time must not be earlier than the stored high-water mark.

- A backward jump locks the licensed pack with a clock warning. Fix the date
  (automatic date/time is easiest) and reopen; the license file stays in place.
- The guard records the highest wall time it has seen. A large forward change
  followed by a backward change is also treated as rollback. If automatic
  date/time is still behind that recorded time, use the pack passphrase.
- The guard updates at most about every five minutes, so very small adjustments
  inside the tolerance are not treated as tampering.
- This is a speed bump, not a trusted-time source. A reboot followed by a date
  after the last-seen time but before expiry can still open the pack. Root,
  Frida, a repackaged APK, or a patched check bypasses it.
- Clearing app data or uninstalling deletes the guard state and the Keystore key;
  a new activation/license is still required, but the new install starts with a
  fresh clock baseline.
- If the guard state cannot be decrypted, the app logs it and starts a fresh
  baseline rather than bricking a valid license. The license checks still apply.

## Troubleshooting

| Message | Meaning / fix |
| --- | --- |
| `This license belongs to another device` | Activation came from another install. Generate a new code on this device and reissue. |
| `License has expired` | Issue a new license with a later expiry. |
| `Could not decrypt the license on this device` | The Android Keystore key changed (reinstall/cleared data) or the license was edited. Get a new activation code and license. |
| `License was signed by an unknown key` | The app does not contain the public key used to sign it. Rebuild with the matching key or issue with the pinned key. |
| `This license belongs to a different pack` | The license was issued for another `.enclib` pack ID. |
| `The device clock was changed backward` | The clock moved back more than the guard allows. Turn on automatic date/time, reopen the pack, then retry the license. The license was not deleted. |
| `Could not store the license` | App storage problem; check free space and retry. |

## Security checklist

- [ ] Full pack passphrase is not in the APK, bridge, or repository.
- [ ] Only the ECDSA public key is committed.
- [ ] `tools/keys/` is gitignored and backed up offline.
- [ ] The local web generator is bound to `127.0.0.1` and is not exposed publicly.
- [ ] Test licenses use a short expiry.
- [ ] Each tester gets a device-specific activation/license pair.
- [ ] The pack file's SHA-256 is unchanged by licensing.
- [ ] Content/app distribution rights are confirmed before public release.
