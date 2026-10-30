"""Vercel Python serverless function for the Encore license generator.

Flask app served by Vercel's Python runtime (see vercel.json rewrites):
  GET  /           the license UI (admin token asked once, stored in the tab)
  POST /api/issue  issue a license (gated by the X-Admin-Token header)

Configuration (environment variables, set in the Vercel dashboard or CLI):
  ENCLIB_SIGNING_KEY       Required. PEM text of the ECDSA P-256 signing private
                           key. Literal newlines or \\n escapes both work.
  ENCLIB_ADMIN_TOKEN       Required. Long random token; the UI prompts for it.
  ENCLIB_PASSPHRASE_<NAME> Passphrase values. packs.json maps a friendly name
                           (lowercase, dashes) to the env var
                           ENCLIB_PASSPHRASE_<UPPERCASED, DASHES TO UNDERSCORES>.
  ENCLIB_PACKS_FILE        Optional override for the packs.json location.

Public pack metadata lives in packs.json at the repo root (pack ID, song count,
size). The signing key, passphrases, and admin token never enter git and are
excluded from deployments via .vercelignore.
"""
from __future__ import annotations

import argparse
import contextlib
import hmac
import io
import json
import os
import tempfile
import traceback
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, Response, request

from tools import enclib_license as lic
from tools.main import (
    MAX_ACTIVATION_CHARS,
    MAX_PASSPHRASE_CHARS,
    LicenseError,
    _page,
)

ROOT = Path(__file__).resolve().parent.parent
PACKS_FILE = Path(os.environ.get("ENCLIB_PACKS_FILE", "")) if os.environ.get("ENCLIB_PACKS_FILE") else ROOT / "packs.json"
STUB_PREFIX = lic.MAGIC + b"\x00" * 8  # MAGIC (8B) + reserved (8B)

app = Flask(__name__)


class ApiError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


def _load_packs() -> dict:
    with PACKS_FILE.open(encoding="utf-8") as handle:
        return json.load(handle)


def _write_signing_key() -> Path:
    """Materialize the PEM env var into a temp file for the engine."""
    pem = os.environ.get("ENCLIB_SIGNING_KEY", "").replace("\\n", "\n")
    if "BEGIN" not in pem:
        raise ApiError(500, "Signing key is not configured (ENCLIB_SIGNING_KEY).")
    handle = tempfile.NamedTemporaryFile(
        mode="w", suffix=".pem", delete=False, encoding="utf-8"
    )
    try:
        handle.write(pem)
    finally:
        handle.close()
    return Path(handle.name)


def _admin_ok(supplied: str) -> bool:
    token = os.environ.get("ENCLIB_ADMIN_TOKEN", "")
    if not token:
        raise ApiError(500, "Admin token is not configured (ENCLIB_ADMIN_TOKEN).")
    return hmac.compare_digest(supplied or "", token)


def _pack_stub(pack_id_hex: str) -> Path:
    """Minimal .enclib header so the engine reads the right pack ID.

    issue() only reads the 80-byte header (magic + pack ID at bytes 16..32), so
    the stub avoids shipping the real pack binary to the server.
    """
    try:
        raw_id = bytes.fromhex(pack_id_hex)
    except ValueError as exc:
        raise ApiError(400, "Unknown pack selection.") from exc
    if len(raw_id) != 16:
        raise ApiError(400, "Unknown pack selection.")
    stub = STUB_PREFIX + raw_id + b"\x00" * (lic.HEADER_SIZE - 32)
    handle = tempfile.NamedTemporaryFile(delete=False)
    try:
        handle.write(stub)
    finally:
        handle.close()
    return Path(handle.name)


def _passphrase_by_name(friendly: str) -> str:
    """Look up a passphrase env var by its packs.json name.

    The name is restricted to alphanumerics and dashes, so request data can only
    reach env vars prefixed ENCLIB_PASSPHRASE_ — never arbitrary ones.
    """
    if not friendly or len(friendly) > 64:
        raise ApiError(400, "Invalid passphrase selection.")
    if not all(ch.isalnum() or ch == "-" for ch in friendly):
        raise ApiError(400, "Invalid passphrase selection.")
    return os.environ.get("ENCLIB_PASSPHRASE_" + friendly.upper().replace("-", "_"), "")


def _resolve_pack(packs: list[dict], name: str) -> dict:
    for pack in packs:
        if pack.get("name") == name:
            return pack
    raise ApiError(400, "That pack is no longer available. Reload the page.")


def _resolve_passphrase(passphrases: list[dict], name: str) -> dict:
    for entry in passphrases:
        if entry.get("name") == name:
            return entry
    raise ApiError(400, "That passphrase selection is no longer available.")


def _key_id() -> str:
    """Key ID shown in the page header, from the configured signing key."""
    key_path = _write_signing_key()
    try:
        signing_key = lic.load_signing_key(key_path)
        return lic.key_id(signing_key.public_key())
    finally:
        key_path.unlink(missing_ok=True)


_INJECT_AFTER_CONFIG = """
const CONFIG = window.__CONFIG__;

let __adminToken = sessionStorage.getItem("enclib-admin") || "";
function adminToken() {
  if (!__adminToken) {
    const entered = window.prompt("Admin token required for this generator", "");
    __adminToken = (entered || "").trim();
    if (__adminToken) sessionStorage.setItem("enclib-admin", __adminToken);
  }
  return __adminToken;
}
function forgetAdminToken() {
  __adminToken = "";
  sessionStorage.removeItem("enclib-admin");
}
"""

# fetch() header injection + 401 recovery, applied to the rendered page.
_FETCH_OLD = '"X-CSRF-Token": CONFIG.csrf,'
_FETCH_NEW = '"X-CSRF-Token": CONFIG.csrf,\n        "X-Admin-Token": adminToken(),'
_THROW_OLD = (
    'if (!response.ok || !data.ok) throw new Error'
    '(data.error || "Could not generate the license.");'
)
_THROW_NEW = (
    'if (!response.ok || !data.ok) {'
    ' if (response.status === 401) forgetAdminToken();'
    ' throw new Error(data.error || "Could not generate the license."); }'
)


def _serve_page() -> str:
    data = _load_packs()
    config = {
        "csrf": "",  # unused serverless; the admin token gates instead
        "keyId": _key_id(),
        "packs": [
            {
                "name": pack["name"],
                "packId": pack.get("packId", ""),
                "songs": int(pack.get("songs", 0)),
                "size": int(pack.get("size", 0)),
            }
            for pack in data.get("packs", [])
        ],
        "passphrases": [entry["name"] for entry in data.get("passphrases", [])],
    }
    html = _page(config)
    # Adapt the local-tool page for serverless: admin-token prompt on fetch,
    # 401 recovery, and honest copy in the badges/footer.
    html = html.replace("const CONFIG = window.__CONFIG__;", _INJECT_AFTER_CONFIG, 1)
    html = html.replace(_FETCH_OLD, _FETCH_NEW, 1)
    html = html.replace(_THROW_OLD, _THROW_NEW, 1)
    html = html.replace("Runs on 127.0.0.1", "Serverless · token-gated", 1)
    html = html.replace(
        "Local-only tool. Close the terminal to stop it.",
        "Hosted deployment. Issuing is gated by the admin token.",
    )
    return html


def _issue(body: dict) -> tuple[str, str, dict]:
    data = _load_packs()
    packs = data.get("packs", [])
    passphrases = data.get("passphrases", [])

    pack_name = str(body.get("pack", "") or "")
    pack = _resolve_pack(packs, pack_name)
    pack_stub = _pack_stub(str(pack.get("packId", "")))

    passphrase_file = str(body.get("passphraseFile", "") or "")
    manual = str(body.get("passphrase", "") or "")
    if passphrase_file:
        _resolve_passphrase(passphrases, passphrase_file)
        passphrase = _passphrase_by_name(passphrase_file)
        if not passphrase:
            raise ApiError(
                500,
                "Passphrase is not configured on the server (ENCLIB_PASSPHRASE_"
                + passphrase_file.upper().replace("-", "_")
                + ").",
            )
    else:
        passphrase = manual
        if len(passphrase) > MAX_PASSPHRASE_CHARS:
            raise ApiError(400, "The passphrase is too long.")
        if len(passphrase) < 8:
            raise ApiError(400, "Enter the pack passphrase (at least 8 characters).")

    try:
        days = int(body.get("days", 30) or 30)
    except (TypeError, ValueError) as exc:
        raise ApiError(400, "Validity must be a number of days.") from exc
    if days < 1 or days > 365:
        raise ApiError(400, "Validity must be between 1 and 365 days.")

    activation = str(body.get("activation", "") or "").strip()
    if not activation:
        raise ApiError(400, "Paste the tester's activation code.")
    if len(activation) > MAX_ACTIVATION_CHARS:
        raise ApiError(400, "The activation code is too long.")

    key_path = _write_signing_key()
    try:
        with tempfile.TemporaryDirectory(prefix="enclib-api-") as temp_dir:
            output = Path(temp_dir) / "license.json"
            args = argparse.Namespace(
                activation=None,
                activation_code=activation,
                pack=str(pack_stub),
                key=str(key_path),
                passphrase=passphrase,
                passphrase_file=None,
                expires=None,
                days=days,
                out=str(output),
                force=True,
            )
            try:
                with contextlib.redirect_stdout(io.StringIO()):
                    lic.issue(args)
            except SystemExit as exc:
                message = str(exc).strip()
                raise LicenseError(message or "Could not generate the license.") from exc
            except LicenseError:
                raise
            except Exception as exc:
                raise LicenseError("Could not generate the license.") from exc
            license_text = output.read_text(encoding="utf-8")
    finally:
        key_path.unlink(missing_ok=True)
        pack_stub.unlink(missing_ok=True)

    try:
        outer = json.loads(license_text)
        payload = json.loads(lic.b64d(outer["payload"]).decode("utf-8"))
        expires = datetime.fromtimestamp(
            int(payload["expiresAt"]) / 1000, tz=timezone.utc
        ).strftime("%Y-%m-%d %H:%M:%SZ")
    except Exception as exc:
        raise ApiError(500, "The generated license could not be verified.") from exc

    device = str(payload.get("deviceKeySha256", ""))
    pack_id_value = str(payload.get("packId", ""))
    filename = f"license-{device[:8]}-{pack_id_value[:8]}.json"
    meta = {
        "packId": pack_id_value,
        "device": device,
        "expiresAt": int(payload.get("expiresAt", 0)),
        "expires": expires,
        "filename": filename,
    }
    return license_text, pack_name, meta


def _json(status: int, payload: dict) -> Response:
    return Response(
        json.dumps(payload),
        status=status,
        content_type="application/json",
    )


@app.get("/")
def page() -> Response:
    try:
        return Response(_serve_page(), status=200, content_type="text/html; charset=utf-8")
    except ApiError as exc:
        return _json(exc.status, {"ok": False, "error": exc.message})


@app.post("/api/issue")
def issue() -> Response:
    try:
        if not _admin_ok(request.headers.get("X-Admin-Token", "")):
            return _json(401, {"ok": False, "error": "Admin token missing or wrong."})
        raw = request.get_data()
        if len(raw) > 64 * 1024:
            return _json(413, {"ok": False, "error": "Request too large."})
        try:
            body = json.loads(raw.decode("utf-8"))
        except Exception as exc:
            return _json(400, {"ok": False, "error": "Request body must be JSON."})
        if not isinstance(body, dict):
            return _json(400, {"ok": False, "error": "Request body must be a JSON object."})
        license_text, pack_name, meta = _issue(body)
        return _json(
            200,
            {"ok": True, "license": license_text, "packName": pack_name, **meta},
        )
    except ApiError as exc:
        return _json(exc.status, {"ok": False, "error": exc.message})
    except LicenseError as exc:
        return _json(400, {"ok": False, "error": str(exc)})
    except Exception:
        traceback.print_exc()
        return _json(500, {"ok": False, "error": "Internal server error."})
