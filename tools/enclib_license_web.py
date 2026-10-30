#!/usr/bin/env python3
"""Local-only web UI for issuing Encore .enclib licenses.

Run this on the pack owner's computer:

    python tools/enclib_license_web.py

It binds to 127.0.0.1 only and serves a form at http://127.0.0.1:8765.
The signing private key and pack passphrases stay on this computer. Nothing is
sent to a remote service. Do not put this behind a public reverse proxy.

The web UI is a thin wrapper around enclib_license.py; the command-line tool
remains the authoritative implementation.
"""

from __future__ import annotations

import argparse
import contextlib
import hmac
import html
import io
import json
import secrets
import struct
import sys
import tempfile
import threading
import webbrowser
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

try:  # Run as a script (`python tools/enclib_license_web.py`).
    import enclib_license as lic
except ImportError:  # Import as `tools.enclib_license_web`.
    from tools import enclib_license as lic


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_PACK_DIR = ROOT / "test-output"
DEFAULT_PASSPHRASE_DIR = ROOT / "test-output"
MAX_REQUEST_BYTES = 64 * 1024
MAX_PASSPHRASE_CHARS = 8192
MAX_ACTIVATION_CHARS = 32 * 1024


class LicenseError(Exception):
    """A user-facing license-generation error."""


def _resolve_listed_file(directory: Path, name: str) -> Path:
    """Resolve a filename from a server-produced list without allowing paths."""
    if not name or name != Path(name).name:
        raise LicenseError("Invalid file selection.")
    base = directory.resolve()
    path = (base / name).resolve()
    if path.parent != base or not path.is_file():
        raise LicenseError("That file is no longer available. Reload the page.")
    return path


def _pack_info(path: Path) -> dict:
    with path.open("rb") as handle:
        raw = handle.read(80)
    if len(raw) < 80 or raw[:8] != lic.MAGIC:
        raise ValueError("bad pack header")
    return {
        "name": path.name,
        "packId": raw[16:32].hex(),
        "songs": struct.unpack_from("<I", raw, 68)[0],
        "size": path.stat().st_size,
    }


def list_packs(pack_dir: Path) -> list[dict]:
    if not pack_dir.is_dir():
        return []
    packs = []
    for path in pack_dir.glob("*.enclib"):
        try:
            packs.append(_pack_info(path))
        except (OSError, ValueError):
            continue
    return sorted(packs, key=lambda item: (-item["size"], item["name"].lower()))


def list_passphrase_files(passphrase_dir: Path) -> list[str]:
    """Return only single-line files that can safely be used as passphrases."""
    if not passphrase_dir.is_dir():
        return []
    names = []
    for path in sorted(passphrase_dir.glob("*.txt")):
        # Activation-code files are also one-line text. Keep the picker focused
        # on intentional passphrase-only files.
        if "passphrase" not in path.name.lower():
            continue
        try:
            text = path.read_text(encoding="utf-8").rstrip("\r\n")
        except (OSError, UnicodeError):
            continue
        if "\n" in text or "\r" in text or len(text) < 8:
            continue
        names.append(path.name)
    return names


def _read_passphrase_file(path: Path) -> str:
    try:
        text = path.read_text(encoding="utf-8").rstrip("\r\n")
    except (OSError, UnicodeError) as exc:
        raise LicenseError("Could not read the selected passphrase file.") from exc
    if "\n" in text or "\r" in text:
        raise LicenseError(
            "The passphrase file must contain only the passphrase on one line."
        )
    if len(text) < 8:
        raise LicenseError("The passphrase must be at least 8 characters.")
    return text


def generate_license(
    *,
    activation: str,
    pack_dir: Path,
    pack_name: str,
    passphrase_dir: Path,
    passphrase_file: str,
    manual_passphrase: str,
    days: int,
    key_path: Path,
) -> tuple[bytes, dict]:
    """Build a license through enclib_license.issue() and return its metadata."""
    activation = (activation or "").strip()
    if not activation:
        raise LicenseError("Paste the tester's activation code.")
    if len(activation) > MAX_ACTIVATION_CHARS:
        raise LicenseError("The activation code is too long.")
    if days < 1 or days > 365:
        raise LicenseError("Validity must be between 1 and 365 days.")

    pack_path = _resolve_listed_file(pack_dir, pack_name)
    if passphrase_file:
        passphrase_path = _resolve_listed_file(passphrase_dir, passphrase_file)
        passphrase = _read_passphrase_file(passphrase_path)
    else:
        passphrase = manual_passphrase or ""
        if len(passphrase) > MAX_PASSPHRASE_CHARS:
            raise LicenseError("The passphrase is too long.")
        if len(passphrase) < 8:
            raise LicenseError("Enter the pack passphrase (at least 8 characters).")

    with tempfile.TemporaryDirectory(prefix="encore-license-") as temp_dir:
        output = Path(temp_dir) / "license.json"
        args = argparse.Namespace(
            activation=None,
            activation_code=activation,
            pack=str(pack_path),
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
        except Exception as exc:
            raise LicenseError("Could not generate the license.") from exc
        data = output.read_bytes()

    try:
        outer = json.loads(data.decode("utf-8"))
        payload = json.loads(lic.b64d(outer["payload"]).decode("utf-8"))
        expires = datetime.fromtimestamp(
            int(payload["expiresAt"]) / 1000, tz=timezone.utc
        ).strftime("%Y-%m-%d %H:%M:%SZ")
    except Exception as exc:
        raise LicenseError("The generated license could not be verified.") from exc

    filename = (
        f"license-{str(payload.get('deviceKeySha256', ''))[:8]}-"
        f"{str(payload.get('packId', ''))[:8]}.json"
    )
    return data, {
        "packId": payload.get("packId", ""),
        "device": payload.get("deviceKeySha256", ""),
        "expiresAt": int(payload.get("expiresAt", 0)),
        "expires": expires,
        "filename": filename,
    }


def _format_size(size: int) -> str:
    if size >= 1024 * 1024 * 1024:
        return f"{size / (1024 ** 3):.2f} GiB"
    if size >= 1024 * 1024:
        return f"{size / (1024 ** 2):.1f} MiB"
    if size >= 1024:
        return f"{size / 1024:.1f} KiB"
    return f"{size} B"


_PAGE_CSS = """
:root {
  color-scheme: dark;
  --blue: #0a84ff;
  --green: #30d158;
  --red: #ff453a;
  --text: #f5f5f7;
  --text-2: rgba(235, 235, 245, 0.68);
  --text-3: rgba(235, 235, 245, 0.5);
  --field: rgba(255, 255, 255, 0.06);
  --field-hover: rgba(255, 255, 255, 0.09);
  --stroke: rgba(255, 255, 255, 0.14);
  --stroke-soft: rgba(255, 255, 255, 0.09);
  --radius-lg: 24px;
  --radius-md: 13px;
  --font: -apple-system, BlinkMacSystemFont, "SF Pro Text", "Segoe UI", Roboto,
    "Helvetica Neue", Arial, sans-serif;
  --mono: ui-monospace, "SF Mono", SFMono-Regular, Menlo, Consolas, monospace;
}

* { box-sizing: border-box; }
html, body { margin: 0; }

body {
  min-height: 100vh;
  background: #05070d;
  color: var(--text);
  font: 15px/1.55 var(--font);
  letter-spacing: -0.006em;
  -webkit-font-smoothing: antialiased;
}

/* Ambient background: drifting color orbs that glow through the frosted glass. */
.backdrop {
  position: fixed;
  inset: 0;
  z-index: -1;
  overflow: hidden;
  pointer-events: none;
  background:
    radial-gradient(1100px 700px at 85% -10%, rgba(191, 90, 242, 0.13), transparent 60%),
    radial-gradient(900px 620px at -10% 24%, rgba(100, 210, 255, 0.11), transparent 55%),
    #05070d;
}
.orb {
  position: absolute;
  border-radius: 50%;
  filter: blur(90px);
  opacity: 0.5;
  will-change: transform;
}
.orb-a {
  width: 560px; height: 560px;
  left: -140px; top: -160px;
  background: radial-gradient(circle at 30% 30%, rgba(10, 132, 255, 0.55), transparent 65%);
  animation: drift-a 28s ease-in-out infinite alternate;
}
.orb-b {
  width: 640px; height: 640px;
  right: -200px; top: 120px;
  background: radial-gradient(circle at 60% 40%, rgba(191, 90, 242, 0.42), transparent 65%);
  animation: drift-b 34s ease-in-out infinite alternate;
}
.orb-c {
  width: 520px; height: 520px;
  left: 30%; bottom: -240px;
  background: radial-gradient(circle at 50% 50%, rgba(48, 209, 88, 0.28), transparent 65%);
  animation: drift-c 38s ease-in-out infinite alternate;
}
@keyframes drift-a {
  from { transform: translate3d(0, 0, 0) scale(1); }
  to { transform: translate3d(90px, 70px, 0) scale(1.12); }
}
@keyframes drift-b {
  from { transform: translate3d(0, 0, 0) scale(1.05); }
  to { transform: translate3d(-110px, 90px, 0) scale(0.95); }
}
@keyframes drift-c {
  from { transform: translate3d(0, 0, 0) scale(1); }
  to { transform: translate3d(70px, -80px, 0) scale(1.1); }
}

main {
  width: min(900px, calc(100% - 40px));
  margin: 0 auto;
  padding: 56px 0 40px;
}

/* Header */
.eyebrow-pill {
  display: inline-flex;
  align-items: center;
  gap: 7px;
  border: 1px solid var(--stroke);
  background: var(--field);
  -webkit-backdrop-filter: blur(12px);
  backdrop-filter: blur(12px);
  border-radius: 999px;
  padding: 5px 12px;
  color: var(--text-2);
  font-size: 11px;
  font-weight: 600;
  letter-spacing: 0.14em;
  text-transform: uppercase;
  box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.12);
}
.eyebrow-pill .dot {
  width: 6px; height: 6px;
  border-radius: 50%;
  background: var(--green);
  box-shadow: 0 0 8px rgba(48, 209, 88, 0.9);
}
h1 {
  margin: 14px 0 8px;
  font-size: clamp(32px, 5vw, 48px);
  line-height: 1.06;
  font-weight: 700;
  letter-spacing: -0.022em;
  background: linear-gradient(100deg, #ffffff 30%, #9ecbff 70%, #d5b3ff 100%);
  -webkit-background-clip: text;
  background-clip: text;
  color: transparent;
}
h2 { margin: 0; font-size: 22px; font-weight: 700; letter-spacing: -0.014em; }
.lede { margin: 0 0 16px; color: var(--text-2); max-width: 640px; }
.badges { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 28px; }
.badges span {
  border: 1px solid var(--stroke-soft);
  background: var(--field);
  -webkit-backdrop-filter: blur(10px);
  backdrop-filter: blur(10px);
  color: var(--text-2);
  border-radius: 999px;
  padding: 4px 11px;
  font-size: 12px;
  box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.08);
}

/* Frosted glass cards */
.card {
  position: relative;
  background: linear-gradient(180deg, rgba(255, 255, 255, 0.10), rgba(255, 255, 255, 0.045));
  -webkit-backdrop-filter: blur(24px) saturate(170%);
  backdrop-filter: blur(24px) saturate(170%);
  border: 1px solid var(--stroke);
  border-radius: var(--radius-lg);
  padding: 26px;
  margin-bottom: 20px;
  box-shadow:
    0 24px 70px rgba(0, 0, 0, 0.45),
    inset 0 1px 0 rgba(255, 255, 255, 0.16);
}

label {
  display: block;
  margin: 0 0 6px;
  font-weight: 600;
  font-size: 13.5px;
  letter-spacing: -0.01em;
}
.grid { display: grid; grid-template-columns: 1.5fr 1fr; gap: 18px; }
.field { margin-top: 16px; }
.hint { display: block; margin-top: 6px; color: var(--text-2); font-size: 12px; font-weight: 400; }

input, select, textarea {
  width: 100%;
  border: 1px solid var(--stroke-soft);
  border-radius: var(--radius-md);
  background: var(--field);
  color: var(--text);
  padding: 11px 14px;
  font: inherit;
  outline: none;
  transition: border-color 0.18s ease, box-shadow 0.18s ease, background-color 0.18s ease;
  box-shadow: inset 0 1px 2px rgba(0, 0, 0, 0.18);
}
input:hover, select:hover, textarea:hover { background: var(--field-hover); }
input:focus, select:focus, textarea:focus {
  border-color: rgba(10, 132, 255, 0.85);
  background: var(--field-hover);
  box-shadow: 0 0 0 4px rgba(10, 132, 255, 0.22), inset 0 1px 2px rgba(0, 0, 0, 0.18);
}
::placeholder { color: var(--text-3); }
select option { background: #1d1d24; color: var(--text); }

textarea {
  resize: vertical;
  font-family: var(--mono);
  font-size: 12px;
  line-height: 1.6;
}

.select-wrap { position: relative; }
.select-wrap select {
  appearance: none;
  -webkit-appearance: none;
  padding-right: 40px;
  cursor: pointer;
}
.select-wrap::after {
  content: "";
  position: absolute;
  right: 17px;
  top: 50%;
  width: 8px;
  height: 8px;
  border-right: 1.8px solid var(--text-2);
  border-bottom: 1.8px solid var(--text-2);
  transform: translateY(-70%) rotate(45deg);
  pointer-events: none;
}

.inline { display: flex; align-items: center; gap: 9px; }
.inline input { max-width: 110px; }
.inline span { color: var(--text-2); }

/* Buttons: Apple pill, press-scale, blue system accent */
button {
  border: 0;
  border-radius: 999px;
  padding: 11px 20px;
  cursor: pointer;
  font: inherit;
  font-weight: 600;
  letter-spacing: -0.01em;
  color: #ffffff;
  background: linear-gradient(180deg, #2c9cff, #0a84ff 55%, #0a7aff);
  box-shadow:
    0 10px 26px rgba(10, 132, 255, 0.35),
    inset 0 1px 0 rgba(255, 255, 255, 0.30);
  transition: transform 0.14s ease, filter 0.18s ease, background-color 0.18s ease;
}
button:hover { filter: brightness(1.09); }
button:active { transform: scale(0.97); }
button:focus-visible { outline: 2px solid #7cc0ff; outline-offset: 2px; }
button:disabled { opacity: 0.5; cursor: wait; transform: none; }
button.secondary {
  background: var(--field);
  border: 1px solid var(--stroke);
  color: var(--text);
  box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.12);
  -webkit-backdrop-filter: blur(10px);
  backdrop-filter: blur(10px);
}
button.secondary:hover { background: var(--field-hover); }
#generate { margin-top: 22px; min-width: 190px; padding: 12px 24px; }

/* Error and result states: tinted glass, measured against the dark canvas */
.error {
  margin-top: 18px;
  border: 1px solid rgba(255, 69, 58, 0.38);
  background: rgba(255, 69, 58, 0.12);
  -webkit-backdrop-filter: blur(12px);
  backdrop-filter: blur(12px);
  color: #ffd6d1;
  border-radius: var(--radius-md);
  padding: 12px 15px;
  white-space: pre-wrap;
}
.result { border-color: rgba(48, 209, 88, 0.30); }
.result-head { display: flex; justify-content: space-between; align-items: flex-start; gap: 12px; }
.ok {
  color: #c4f7d3;
  background: rgba(48, 209, 88, 0.16);
  border: 1px solid rgba(48, 209, 88, 0.42);
  border-radius: 999px;
  padding: 4px 11px;
  font-size: 11px;
  font-weight: 700;
  letter-spacing: 0.1em;
}
.summary {
  display: grid;
  grid-template-columns: max-content 1fr;
  gap: 9px 20px;
  margin: 20px 0;
  padding: 16px 18px;
  border: 1px solid var(--stroke-soft);
  border-radius: var(--radius-md);
  background: rgba(0, 0, 0, 0.16);
}
.summary dt { color: var(--text-2); font-size: 13px; }
.summary dd { margin: 0; overflow-wrap: anywhere; font-size: 14px; }
.actions { display: flex; flex-wrap: wrap; gap: 10px; margin-bottom: 14px; }
#license-text { background: rgba(0, 0, 0, 0.25); }

footer { color: var(--text-2); text-align: center; font-size: 12px; margin-top: 26px; }

.sr-only {
  position: absolute;
  width: 1px; height: 1px;
  padding: 0; margin: -1px;
  overflow: hidden;
  clip: rect(0, 0, 0, 0);
  white-space: nowrap;
  border: 0;
}
[hidden] { display: none !important; }

::selection { background: rgba(10, 132, 255, 0.45); }

@media (prefers-reduced-motion: no-preference) {
  header, .card { animation: rise 0.55s cubic-bezier(0.22, 1, 0.36, 1) both; }
  .card { animation-delay: 0.07s; }
}
@keyframes rise {
  from { opacity: 0; transform: translateY(14px); }
  to { opacity: 1; transform: translateY(0); }
}
@media (prefers-reduced-motion: reduce) {
  .orb { animation: none; }
}

@media (max-width: 650px) {
  main { padding-top: 30px; }
  .grid { grid-template-columns: 1fr; gap: 0; }
  .card { padding: 19px; border-radius: 20px; }
  .orb { filter: blur(70px); }
}
"""


def _page(config: dict) -> str:
    config_json = (
        json.dumps(config, ensure_ascii=True, separators=(",", ":"))
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("&", "\\u0026")
    )
    key_id = html.escape(str(config.get("keyId", "")))
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Encore License Generator</title>
<style>
{_PAGE_CSS}
</style>
</head>
<body>
<div class="backdrop" aria-hidden="true">
  <div class="orb orb-a"></div>
  <div class="orb orb-b"></div>
  <div class="orb orb-c"></div>
</div>
<main>
  <header>
    <span class="eyebrow-pill"><span class="dot" aria-hidden="true"></span>Encore · Local License Tool</span>
    <h1>License Generator</h1>
    <p class="lede">Sign a device-bound license without sending the pack passphrase or signing key off this computer.</p>
    <div class="badges"><span>Runs on 127.0.0.1</span><span>Signing key {key_id}</span></div>
  </header>

  <section class="card">
    <form id="license-form">
      <div class="field">
        <label for="activation">Activation code</label>
        <textarea id="activation" rows="5" placeholder="ENCLIB-ACT-1:..." spellcheck="false" autocomplete="off" required></textarea>
        <span class="hint">Paste the code from Library Manager → Device License.</span>
      </div>

      <div class="grid field">
        <div>
          <label for="pack">Pack</label>
          <div class="select-wrap"><select id="pack"></select></div>
          <span id="pack-meta" class="hint"></span>
        </div>
        <div>
          <label for="days">Valid for</label>
          <div class="inline"><input id="days" type="number" min="1" max="365" value="14" required><span>days</span></div>
        </div>
      </div>

      <div class="field">
        <label for="pass-source">Passphrase source</label>
        <div class="select-wrap"><select id="pass-source"></select></div>
        <span id="pass-hint" class="hint"></span>
      </div>

      <div id="manual-pass-wrap" class="field" hidden>
        <label for="passphrase">Pack passphrase</label>
        <input id="passphrase" type="password" autocomplete="off" spellcheck="false">
        <span class="hint">Used only by this local process. It is not stored or sent to another server.</span>
      </div>

      <button id="generate" type="submit">Generate license</button>
      <div id="error" class="error" role="alert" hidden></div>
    </form>
  </section>

  <section id="result" class="card result" hidden>
    <div class="result-head">
      <div><div class="eyebrow">READY</div><h2 id="result-title">License generated</h2></div>
      <span class="ok">SIGNED</span>
    </div>
    <dl id="summary" class="summary"></dl>
    <div class="actions">
      <button id="download" type="button">Download .json</button>
      <button id="copy" type="button" class="secondary">Copy JSON</button>
      <button id="another" type="button" class="secondary">Generate another</button>
    </div>
    <label class="sr-only" for="license-text">License JSON</label>
    <textarea id="license-text" rows="10" readonly spellcheck="false"></textarea>
    <span class="hint">Send only this file or text to the tester. Never send the passphrase or signing key.</span>
  </section>

  <footer>Local-only tool. Close the terminal to stop it.</footer>
</main>
<script>
window.__CONFIG__ = {config_json};
const CONFIG = window.__CONFIG__;
const $ = (id) => document.getElementById(id);
const form = $("license-form");
const packSelect = $("pack");
const passSource = $("pass-source");
const manualWrap = $("manual-pass-wrap");
const passphrase = $("passphrase");
const errorBox = $("error");
const resultBox = $("result");
const generateButton = $("generate");
let current = null;

function formatBytes(n) {{
  if (n >= 1024 * 1024 * 1024) return (n / (1024 ** 3)).toFixed(2) + " GiB";
  if (n >= 1024 * 1024) return (n / (1024 ** 2)).toFixed(1) + " MiB";
  if (n >= 1024) return (n / 1024).toFixed(1) + " KiB";
  return n + " B";
}}

function setError(message) {{
  errorBox.textContent = message || "";
  errorBox.hidden = !message;
}}

function updatePackMeta() {{
  const pack = CONFIG.packs[packSelect.selectedIndex];
  $("pack-meta").textContent = pack
    ? pack.songs.toLocaleString() + " songs · " + pack.packId.slice(0, 12) + "… · " + formatBytes(pack.size)
    : "";
}}

function syncPassphraseSource() {{
  const manual = !passSource.value;
  manualWrap.hidden = !manual;
  $("pass-hint").textContent = manual
    ? "Type the exact passphrase. Prefer a passphrase-only file when possible."
    : "The selected file is read by the local server; its contents are never sent to the browser.";
  if (manual) setTimeout(() => passphrase.focus(), 20);
}}

function addSummary(label, value) {{
  const dt = document.createElement("dt");
  dt.textContent = label;
  const dd = document.createElement("dd");
  dd.textContent = value;
  $("summary").append(dt, dd);
}}

for (const pack of CONFIG.packs) {{
  const option = document.createElement("option");
  option.value = pack.name;
  option.textContent = pack.name;
  packSelect.appendChild(option);
}}
if (!CONFIG.packs.length) {{
  const option = document.createElement("option");
  option.textContent = "No .enclib packs found";
  option.value = "";
  packSelect.appendChild(option);
  generateButton.disabled = true;
}}
packSelect.addEventListener("change", updatePackMeta);
updatePackMeta();

const typeOption = document.createElement("option");
typeOption.value = "";
typeOption.textContent = "Type a passphrase";
passSource.appendChild(typeOption);
for (const name of CONFIG.passphrases) {{
  const option = document.createElement("option");
  option.value = name;
  option.textContent = name;
  passSource.appendChild(option);
}}
if (CONFIG.passphrases.length) passSource.value = CONFIG.passphrases[0];
syncPassphraseSource();
passSource.addEventListener("change", syncPassphraseSource);

form.addEventListener("submit", async (event) => {{
  event.preventDefault();
  setError("");
  resultBox.hidden = true;
  generateButton.disabled = true;
  generateButton.textContent = "Generating…";
  const payload = {{
    activation: $("activation").value,
    pack: packSelect.value,
    days: Number($("days").value),
    passphraseFile: passSource.value,
    passphrase: passSource.value ? "" : passphrase.value,
  }};
  try {{
    const response = await fetch("/api/issue", {{
      method: "POST",
      headers: {{
        "Content-Type": "application/json",
        "X-CSRF-Token": CONFIG.csrf,
      }},
      body: JSON.stringify(payload),
    }});
    const data = await response.json().catch(() => ({{ error: "The server returned an invalid response." }}));
    if (!response.ok || !data.ok) throw new Error(data.error || "Could not generate the license.");
    current = data;
    $("summary").replaceChildren();
    addSummary("Pack", data.packName + " (" + data.packId + ")");
    addSummary("Device", data.device.slice(0, 16) + "…");
    addSummary("Expires", data.expires);
    addSummary("File", data.filename);
    $("license-text").value = data.license;
    $("result-title").textContent = "License for " + data.packName;
    resultBox.hidden = false;
    passphrase.value = "";
    resultBox.scrollIntoView({{ behavior: "smooth", block: "start" }});
  }} catch (error) {{
    setError(error && error.message ? error.message : "Could not generate the license.");
  }} finally {{
    generateButton.disabled = false;
    generateButton.textContent = "Generate license";
  }}
}});

$("download").addEventListener("click", () => {{
  if (!current) return;
  const blob = new Blob([current.license], {{ type: "application/json" }});
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = current.filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}});

$("copy").addEventListener("click", async () => {{
  const text = $("license-text").value;
  let copied = false;
  try {{
    await navigator.clipboard.writeText(text);
    copied = true;
  }} catch (error) {{
    try {{
      $("license-text").select();
      copied = document.execCommand("copy");
    }} catch (ignored) {{
      copied = false;
    }}
  }}
  $("copy").textContent = copied ? "Copied" : "Select and copy";
  setTimeout(() => {{ $("copy").textContent = "Copy JSON"; }}, 1800);
}});

$("another").addEventListener("click", () => {{
  resultBox.hidden = true;
  current = null;
  setError("");
  $("activation").focus();
}});
</script>
</body>
</html>
"""


class LicenseHandler(BaseHTTPRequestHandler):
    server_version = "EncoreLicense/1.0"
    sys_version = ""

    def log_message(self, format, *args):  # noqa: A002 - stdlib signature
        # Deliberately do not log request bodies or query strings. The UI never
        # puts secrets in a URL, but keeping the console quiet avoids accidents.
        return

    def _send_common_headers(self):
        self.send_header("Cache-Control", "no-store, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; style-src 'unsafe-inline'; "
            "script-src 'unsafe-inline'; connect-src 'self'; img-src data:; "
            "base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
        )

    def _send_bytes(self, status: int, content_type: str, body: bytes):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self._send_common_headers()
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, status: int, value: dict):
        body = json.dumps(value, ensure_ascii=True).encode("utf-8")
        self._send_bytes(status, "application/json; charset=utf-8", body)

    def _send_error_json(self, status: int, message: str):
        self._send_json(status, {"ok": False, "error": message})

    def _host_ok(self) -> bool:
        host = self.headers.get("Host", "").strip().lower()
        if not host:
            return True
        name = host.rsplit(":", 1)[0].strip("[]")
        return name in {"127.0.0.1", "localhost", "::1"}

    def _origin_ok(self) -> bool:
        origin = self.headers.get("Origin")
        if not origin:
            return True
        port = self.server.server_address[1]
        allowed = {
            f"http://127.0.0.1:{port}",
            f"http://localhost:{port}",
        }
        try:
            parts = urlsplit(origin)
            normalized = f"{parts.scheme}://{parts.netloc}".rstrip("/")
        except ValueError:
            return False
        return normalized in allowed

    def do_GET(self):
        if not self._host_ok():
            self._send_error_json(HTTPStatus.FORBIDDEN, "Unexpected Host header.")
            return
        path = urlsplit(self.path).path
        if path not in {"/", "/index.html"}:
            self._send_error_json(HTTPStatus.NOT_FOUND, "Not found.")
            return
        config = {
            "csrf": self.server.csrf,
            "keyId": self.server.key_id,
            "packs": list_packs(self.server.pack_dir),
            "passphrases": list_passphrase_files(self.server.passphrase_dir),
        }
        page = _page(config).encode("utf-8")
        self._send_bytes(HTTPStatus.OK, "text/html; charset=utf-8", page)

    def do_POST(self):
        if not self._host_ok() or not self._origin_ok():
            self._send_error_json(HTTPStatus.FORBIDDEN, "Untrusted request origin.")
            return
        if urlsplit(self.path).path != "/api/issue":
            self._send_error_json(HTTPStatus.NOT_FOUND, "Not found.")
            return
        if not hmac.compare_digest(
            self.headers.get("X-CSRF-Token", ""), self.server.csrf
        ):
            self._send_error_json(HTTPStatus.FORBIDDEN, "Invalid CSRF token. Reload the page.")
            return
        content_type = self.headers.get("Content-Type", "")
        if not content_type.lower().startswith("application/json"):
            self._send_error_json(
                HTTPStatus.UNSUPPORTED_MEDIA_TYPE, "Expected a JSON request."
            )
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if length <= 0:
            self._send_error_json(HTTPStatus.BAD_REQUEST, "The request body is empty.")
            return
        if length > MAX_REQUEST_BYTES:
            self._send_error_json(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "The request is too large."
            )
            return
        raw = self.rfile.read(length)
        try:
            body = json.loads(raw.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError):
            self._send_error_json(HTTPStatus.BAD_REQUEST, "The request is not valid JSON.")
            return
        if not isinstance(body, dict):
            self._send_error_json(HTTPStatus.BAD_REQUEST, "The request is not valid.")
            return

        activation = body.get("activation", "")
        pack_name = body.get("pack", "")
        passphrase_file = body.get("passphraseFile", "")
        manual_passphrase = body.get("passphrase", "")
        days = body.get("days", 14)
        if not all(
            isinstance(value, str)
            for value in (activation, pack_name, passphrase_file, manual_passphrase)
        ):
            self._send_error_json(HTTPStatus.BAD_REQUEST, "Invalid field types.")
            return
        if isinstance(days, bool) or not isinstance(days, int):
            self._send_error_json(HTTPStatus.BAD_REQUEST, "Validity must be a number.")
            return

        try:
            license_bytes, meta = generate_license(
                activation=activation,
                pack_dir=self.server.pack_dir,
                pack_name=pack_name,
                passphrase_dir=self.server.passphrase_dir,
                passphrase_file=passphrase_file,
                manual_passphrase=manual_passphrase,
                days=days,
                key_path=self.server.key_path,
            )
        except LicenseError as exc:
            self._send_error_json(HTTPStatus.BAD_REQUEST, str(exc))
            return
        except Exception as exc:  # pragma: no cover - defensive
            print(
                f"License web tool: unexpected {type(exc).__name__}",
                file=sys.stderr,
            )
            self._send_error_json(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                "License generation failed. See the terminal for details.",
            )
            return

        pack = next(
            (item for item in list_packs(self.server.pack_dir)
             if item["name"] == pack_name),
            {"name": pack_name},
        )
        self._send_json(
            HTTPStatus.OK,
            {
                "ok": True,
                "license": license_bytes.decode("utf-8"),
                "packName": pack.get("name", pack_name),
                **meta,
            },
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Local-only web UI for issuing Encore .enclib licenses. "
            "Binds to 127.0.0.1; do not expose it publicly."
        )
    )
    parser.add_argument("--port", type=int, default=8765, help="port (0 = choose a free port)")
    parser.add_argument(
        "--pack-dir",
        type=Path,
        default=DEFAULT_PACK_DIR,
        help="folder containing .enclib files (default: test-output)",
    )
    parser.add_argument(
        "--passphrase-dir",
        type=Path,
        default=DEFAULT_PASSPHRASE_DIR,
        help="folder containing passphrase-only .txt files (default: test-output)",
    )
    parser.add_argument(
        "--key",
        type=Path,
        default=lic.DEFAULT_KEY,
        help="ECDSA signing private key",
    )
    parser.add_argument(
        "--no-browser",
        action="store_true",
        help="do not open a browser automatically",
    )
    args = parser.parse_args(argv)

    if args.port < 0 or args.port > 65535:
        print("Port must be between 0 and 65535.", file=sys.stderr)
        return 2
    pack_dir = args.pack_dir.expanduser().resolve()
    passphrase_dir = args.passphrase_dir.expanduser().resolve()
    key_path = args.key.expanduser().resolve()
    try:
        signing_key = lic.load_signing_key(key_path)
        signing_id = lic.key_id(signing_key.public_key())
    except SystemExit as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except Exception as exc:  # pragma: no cover - operator-facing
        print(f"Could not load the signing key: {type(exc).__name__}", file=sys.stderr)
        return 2

    server = ThreadingHTTPServer(("127.0.0.1", args.port), LicenseHandler)
    server.daemon_threads = True
    server.pack_dir = pack_dir
    server.passphrase_dir = passphrase_dir
    server.key_path = key_path
    server.key_id = signing_id
    server.csrf = secrets.token_urlsafe(32)
    port = server.server_address[1]
    url = f"http://127.0.0.1:{port}/"

    print("Encore local license generator")
    print(f"URL:       {url}")
    print(f"Key ID:    {signing_id}")
    print(f"Pack dir:  {pack_dir}")
    print(f"Pass dir:  {passphrase_dir}")
    print("Local only. Do not expose this port publicly. Press Ctrl+C to stop.")
    if not args.no_browser:
        threading.Timer(0.4, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
