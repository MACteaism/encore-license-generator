#!/usr/bin/env python3
"""Issue manual, device-bound licenses for an .enclib pack.

The pack format does not change. A license is a small JSON file containing the
pack passphrase encrypted to one Android device's Keystore RSA public key. The
license is signed with the pack owner's offline ECDSA key; the app ships only
the matching public key.

Typical flow (no server needed):

  1. Tester installs the app, opens Library Manager, taps "Device License",
     and sends you the activation code it displays.
  2. You run:

       python tools/enclib_license.py issue \
         --activation tester-activation.txt \
         --pack test-output/Encore-Library.enclib \
         --days 14 \
         --out test-output/license-tester.json

     The pack passphrase is read from ENCLIB_PASSPHRASE, --passphrase-file, or
     an interactive prompt. It is never written to the license in plaintext.
  3. Send the license file to the tester. They import the pack, choose
     "Use License File", and select the license.

Commands:
  keygen    Create the offline ECDSA signing key and print the app constant.
  issue     Create one license for one activation code and one pack.
  inspect   Verify a license signature and print its metadata.
  selftest  Exercise activation, wrapping, signing and verification locally.
"""

from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import json
import os
import re
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
except ImportError as exc:  # pragma: no cover - operator-facing message
    raise SystemExit(
        "Missing Python package. Run: python -m pip install cryptography"
    ) from exc

ACTIVATION_PREFIX = "ENCLIB-ACT-1:"
ACTIVATION_FORMAT = "enclib-activation/v1"
LICENSE_FORMAT = "enclib-license/v1"
MAGIC = b"ENCLIB1\0"
HEADER_SIZE = 320
DEFAULT_KEY = Path(__file__).resolve().parent / "keys" / "enclib-license-signing-key.pem"
# RSA-2048 OAEP-SHA256 can wrap at most 190 bytes. Longer passphrases are
# split into chunks; the license stores the concatenated RSA ciphertexts.
OAEP_CHUNK_SIZE = 128


def b64e(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def b64d(value: str) -> bytes:
    # Codes are copied through chat/email and may acquire line wraps.
    compact = "".join(value.split())
    return base64.b64decode(compact.encode("ascii"), validate=True)


def public_key_der(public_key) -> bytes:
    return public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def key_id(public_key) -> str:
    return hashlib.sha256(public_key_der(public_key)).hexdigest()[:16]


def load_signing_key(path: Path):
    if not path.is_file():
        raise SystemExit(
            f"Signing key not found: {path}\n"
            "Run: python tools/enclib_license.py keygen"
        )
    return serialization.load_pem_private_key(path.read_bytes(), password=None)


def read_text(path: Path | None, value: str | None) -> str:
    if path is not None:
        if not path.is_file():
            raise SystemExit(f"File not found: {path}")
        return path.read_text(encoding="utf-8").strip()
    if value:
        return value.strip()
    return sys.stdin.read().strip()


def decode_activation(text: str) -> dict:
    text = text.strip()
    if text.startswith(ACTIVATION_PREFIX):
        raw = b64d(text[len(ACTIVATION_PREFIX) :])
    elif text.startswith("{"):
        raw = text.encode("utf-8")
    else:
        try:
            raw = b64d(text)
        except Exception as exc:
            raise SystemExit("Activation code is not valid Base64.") from exc
    try:
        activation = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise SystemExit("Activation code does not contain valid JSON.") from exc
    if activation.get("format") != ACTIVATION_FORMAT:
        raise SystemExit(f"Unsupported activation format: {activation.get('format')!r}")
    try:
        device_der = b64d(activation["deviceKey"])
        device_key = serialization.load_der_public_key(device_der)
    except Exception as exc:
        raise SystemExit("Activation code has an invalid device key.") from exc
    if not isinstance(device_key, rsa.RSAPublicKey):
        raise SystemExit("The device key is not RSA; this license format needs RSA.")
    digest = hashlib.sha256(device_der).hexdigest()
    claimed = activation.get("deviceKeySha256")
    if claimed and claimed != digest:
        raise SystemExit("Activation code device-key hash does not match its key.")
    activation["_device_key"] = device_key
    activation["_device_der"] = device_der
    activation["_device_sha256"] = digest
    return activation


def pack_id(path: Path) -> str:
    if not path.is_file():
        raise SystemExit(f"Pack not found: {path}")
    with path.open("rb") as handle:
        raw = handle.read(HEADER_SIZE)
    if len(raw) < HEADER_SIZE or raw[:8] != MAGIC:
        raise SystemExit("Not an .enclib file (bad magic).")
    return raw[16:32].hex()


def parse_expiry(expires: str | None, days: int | None) -> int:
    now = datetime.now(timezone.utc)
    if expires:
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}", expires):
            try:
                end = datetime.strptime(expires, "%Y-%m-%d").replace(
                    tzinfo=timezone.utc
                ) + timedelta(days=1) - timedelta(seconds=1)
            except ValueError as exc:
                raise SystemExit("--expires must be YYYY-MM-DD") from exc
            return int(end.timestamp() * 1000)
        if re.fullmatch(r"\d+", expires):
            # Accept an absolute Unix timestamp in seconds or milliseconds.
            value = int(expires)
            return value * 1000 if value < 10_000_000_000 else value
        raise SystemExit("--expires must be YYYY-MM-DD or a Unix timestamp")
    if days is None:
        days = 30
    if days < 1:
        raise SystemExit("--days must be at least 1")
    return int((now + timedelta(days=days)).timestamp() * 1000)


def get_passphrase(args: argparse.Namespace) -> str:
    if args.passphrase_file:
        path = Path(args.passphrase_file)
        if not path.is_file():
            raise SystemExit(f"Passphrase file not found: {path}")
        value = path.read_text(encoding="utf-8").rstrip("\r\n")
        if "\n" in value or "\r" in value:
            raise SystemExit(
                "Passphrase file must contain only the passphrase on one line; "
                "labels or instructions would become part of the key."
            )
    elif args.passphrase is not None:
        value = args.passphrase
    elif os.environ.get("ENCLIB_PASSPHRASE"):
        value = os.environ["ENCLIB_PASSPHRASE"]
    else:
        value = getpass.getpass("Pack passphrase: ")
    if len(value) < 8:
        raise SystemExit("Passphrase must be at least 8 characters.")
    return value


def _oaep_encrypt_chunks(device_key, passphrase: bytes, algorithm) -> bytes:
    """Encrypt a passphrase in OAEP-sized chunks and concatenate ciphertexts."""
    if not passphrase:
        raise SystemExit("Passphrase is empty.")
    block_size = device_key.key_size // 8
    max_plaintext = block_size - 2 * algorithm.digest_size - 2
    if max_plaintext < 1:
        raise SystemExit("Device RSA key is too small for OAEP.")
    chunk_size = min(OAEP_CHUNK_SIZE, max_plaintext)
    output = bytearray()
    for offset in range(0, len(passphrase), chunk_size):
        output.extend(
            device_key.encrypt(
                passphrase[offset : offset + chunk_size],
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=algorithm),
                    algorithm=algorithm,
                    label=None,
                ),
            )
        )
    return bytes(output)


def wrap_passphrase(device_key, passphrase: bytes) -> tuple[str, str]:
    sha256 = _oaep_encrypt_chunks(device_key, passphrase, hashes.SHA256())
    # Android Keystore has used MGF1-SHA1 with the SHA-1 OAEP variant for a long
    # time. Keeping both wraps makes the license work across more devices while
    # the SHA-256 wrap remains the preferred path.
    sha1 = _oaep_encrypt_chunks(device_key, passphrase, hashes.SHA1())
    return b64e(sha256), b64e(sha1)


def issue(args: argparse.Namespace) -> int:
    activation = decode_activation(
        read_text(Path(args.activation) if args.activation else None, args.activation_code)
    )
    device_key = activation["_device_key"]
    device_sha256 = activation["_device_sha256"]
    pack = Path(args.pack)
    pack_id_value = pack_id(pack)
    if activation.get("packId") and activation["packId"] != pack_id_value:
        raise SystemExit(
            "Activation code is bound to a different pack "
            f"({activation['packId']} != {pack_id_value})."
        )

    signing_key = load_signing_key(Path(args.key))
    signing_public = signing_key.public_key()
    signing_id = key_id(signing_public)
    passphrase = get_passphrase(args).encode("utf-8")
    wrapped_sha256, wrapped_sha1 = wrap_passphrase(device_key, passphrase)

    now_ms = int(time.time() * 1000)
    expires_ms = parse_expiry(args.expires, args.days)
    if expires_ms <= now_ms:
        raise SystemExit("Expiry must be in the future.")

    payload = {
        "v": 1,
        "keyId": signing_id,
        "packId": pack_id_value,
        "deviceKeySha256": device_sha256,
        "issuedAt": now_ms,
        "expiresAt": expires_ms,
        "wrappedPassphraseSha256": wrapped_sha256,
        "wrappedPassphraseSha1": wrapped_sha1,
    }
    payload_bytes = json.dumps(
        payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    signature = signing_key.sign(payload_bytes, ec.ECDSA(hashes.SHA256()))
    license_bytes = json.dumps(
        {
            "format": LICENSE_FORMAT,
            "payload": b64e(payload_bytes),
            "signature": b64e(signature),
        },
        indent=2,
    ).encode("utf-8") + b"\n"

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    if out.exists() and not args.force:
        raise SystemExit(f"{out} already exists (use --force to replace it).")
    out.write_bytes(license_bytes)
    expiry_text = datetime.fromtimestamp(expires_ms / 1000, tz=timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%SZ"
    )
    print(f"License:  {out}")
    print(f"Pack ID:  {pack_id_value}")
    print(f"Device:   {device_sha256[:16]}...")
    print(f"Key ID:   {signing_id}")
    print(f"Expires:  {expiry_text}")
    print("The pack passphrase was wrapped to the device key and was not written in plaintext.")
    return 0


def verify_license_file(path: Path, key_path: Path, verbose: bool = True) -> dict:
    if not path.is_file():
        raise SystemExit(f"License not found: {path}")
    try:
        outer = json.loads(path.read_text(encoding="utf-8"))
        if outer.get("format") != LICENSE_FORMAT:
            raise ValueError(f"unsupported format {outer.get('format')!r}")
        payload_bytes = b64d(outer["payload"])
        signature = b64d(outer["signature"])
        payload = json.loads(payload_bytes.decode("utf-8"))
    except SystemExit:
        raise
    except Exception as exc:
        raise SystemExit("License file is not valid.") from exc

    signing_key = load_signing_key(key_path)
    expected_id = key_id(signing_key.public_key())
    if payload.get("keyId") != expected_id:
        raise SystemExit(
            f"License key ID {payload.get('keyId')!r} does not match this signing key."
        )
    try:
        signing_key.public_key().verify(
            signature, payload_bytes, ec.ECDSA(hashes.SHA256())
        )
    except InvalidSignature as exc:
        raise SystemExit("License signature is invalid.") from exc

    expires_ms = int(payload.get("expiresAt", 0))
    expired = expires_ms <= int(time.time() * 1000)
    if verbose:
        expiry_text = datetime.fromtimestamp(expires_ms / 1000, tz=timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%SZ"
        )
        print(f"License:  {path}")
        print(f"Pack ID:  {payload.get('packId')}")
        print(f"Device:   {str(payload.get('deviceKeySha256'))[:16]}...")
        print(f"Key ID:   {payload.get('keyId')}")
        print(f"Expires:  {expiry_text} ({'EXPIRED' if expired else 'valid'})")
        print("Signature: OK")
    payload["_expired"] = expired
    return payload


def inspect(args: argparse.Namespace) -> int:
    verify_license_file(Path(args.license), Path(args.key), verbose=True)
    return 0


def keygen(args: argparse.Namespace) -> int:
    path = Path(args.key)
    if path.exists() and not args.force:
        raise SystemExit(f"{path} already exists (use --force to replace it).")
    path.parent.mkdir(parents=True, exist_ok=True)
    private_key = ec.generate_private_key(ec.SECP256R1())
    path.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    public_key = private_key.public_key()
    public_b64 = b64e(public_key_der(public_key))
    signing_id = key_id(public_key)
    print(f"Private key: {path}")
    print("Keep this file offline. Anyone with it can issue licenses.")
    print()
    print("App constant for EnclibLicense.java:")
    print(f'    public static final String ADMIN_PUBLIC_KEY_B64 = "{public_b64}";')
    print(f'    public static final String ADMIN_KEY_ID = "{signing_id}";')
    return 0


def selftest(args: argparse.Namespace) -> int:
    """Test the wire format without needing an Android device."""
    signing_key = load_signing_key(Path(args.key))
    device_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    device_der = public_key_der(device_key.public_key())
    device_sha256 = hashlib.sha256(device_der).hexdigest()
    activation = {
        "format": ACTIVATION_FORMAT,
        "deviceKey": b64e(device_der),
        "deviceKeySha256": device_sha256,
        "createdAt": int(time.time() * 1000),
    }
    code = ACTIVATION_PREFIX + b64e(
        json.dumps(activation, separators=(",", ":")).encode("utf-8")
    )
    decoded = decode_activation(code)
    assert decoded["_device_sha256"] == device_sha256

    passphrase = b"self-test-passphrase-" + b"x" * 300
    wrapped_sha256, wrapped_sha1 = wrap_passphrase(device_key.public_key(), passphrase)
    block_size = device_key.key_size // 8
    for wrapped, digest in (
        (wrapped_sha256, hashes.SHA256()),
        (wrapped_sha1, hashes.SHA1()),
    ):
        ciphertext = b64d(wrapped)
        assert len(ciphertext) % block_size == 0
        recovered = bytearray()
        for offset in range(0, len(ciphertext), block_size):
            recovered.extend(
                device_key.decrypt(
                    ciphertext[offset : offset + block_size],
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=digest),
                        algorithm=digest,
                        label=None,
                    ),
                )
            )
        assert bytes(recovered) == passphrase

    payload = {
        "v": 1,
        "keyId": key_id(signing_key.public_key()),
        "packId": "00" * 16,
        "deviceKeySha256": device_sha256,
        "issuedAt": int(time.time() * 1000),
        "expiresAt": int(time.time() * 1000) + 60_000,
        "wrappedPassphraseSha256": wrapped_sha256,
        "wrappedPassphraseSha1": wrapped_sha1,
    }
    payload_bytes = json.dumps(
        payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    signature = signing_key.sign(payload_bytes, ec.ECDSA(hashes.SHA256()))
    signing_key.public_key().verify(
        signature, payload_bytes, ec.ECDSA(hashes.SHA256())
    )
    outer = {
        "format": LICENSE_FORMAT,
        "payload": b64e(payload_bytes),
        "signature": b64e(signature),
    }
    print("Self-test passed: activation code, both RSA-OAEP wraps, and ECDSA signature.")
    print("Sample license outer fields:", ", ".join(sorted(outer.keys())))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    keygen_parser = sub.add_parser("keygen", help="Create the offline signing key")
    keygen_parser.add_argument("--key", default=str(DEFAULT_KEY))
    keygen_parser.add_argument("--force", action="store_true")
    keygen_parser.set_defaults(func=keygen)

    issue_parser = sub.add_parser("issue", help="Issue one device-bound license")
    issue_parser.add_argument("--activation", help="File containing the tester's activation code")
    issue_parser.add_argument("--activation-code", help="Activation code as a single argument")
    issue_parser.add_argument("--pack", required=True, help="The .enclib file to license")
    issue_parser.add_argument("--out", required=True, help="Output license JSON")
    issue_parser.add_argument("--key", default=str(DEFAULT_KEY))
    issue_parser.add_argument("--expires", help="Expiry date (YYYY-MM-DD) or Unix timestamp")
    issue_parser.add_argument("--days", type=int, help="Days from now (default: 30)")
    issue_parser.add_argument("--passphrase-file", help="File containing the pack passphrase")
    issue_parser.add_argument("--passphrase", help="Passphrase (avoid: shell history)")
    issue_parser.add_argument("--force", action="store_true")
    issue_parser.set_defaults(func=issue)

    inspect_parser = sub.add_parser("inspect", help="Verify a license file")
    inspect_parser.add_argument("--license", required=True)
    inspect_parser.add_argument("--key", default=str(DEFAULT_KEY))
    inspect_parser.set_defaults(func=inspect)

    selftest_parser = sub.add_parser("selftest", help="Run a local format self-test")
    selftest_parser.add_argument("--key", default=str(DEFAULT_KEY))
    selftest_parser.set_defaults(func=selftest)

    args = parser.parse_args()
    if args.command == "issue" and not (args.activation or args.activation_code):
        parser.error("issue requires --activation or --activation-code")
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
