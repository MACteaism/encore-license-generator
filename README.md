# 🔑 Encore Karaoke — License Generator

<p align="center">
  <img src=".github/assets/logo.jpg" alt="Encore Karaoke License Generator logo" width="192" />
</p>

[![Status](https://img.shields.io/badge/Status-Production-brightgreen.svg)]()
[![Deploy](https://img.shields.io/badge/Deploy-Vercel-black.svg)](https://encore-license-generator.vercel.app)
[![Live](https://img.shields.io/badge/License_generator-Online-success.svg)](https://encore-license-generator.vercel.app)

> A standalone tool for issuing device-bound `.enclib` licenses for the Encore Karaoke Android app — runs as a CLI, a localhost web UI, and a hosted Vercel generator.

## ✨ Key Features

- **Device-Bound Licenses:** Each license encrypts the pack passphrase to one device's non-exportable Android Keystore RSA key — a license cannot be copied to another device.
- **Offline ECDSA Signing:** Licenses are signed with an ECDSA P-256 key; the app ships only the matching public key. Key rotation is supported without invalidating existing licenses.
- **Three Ways to Issue:** CLI (`tools/enclib_license.py`), localhost web UI (`tools/main.py`), and a hosted generator at https://encore-license-generator.vercel.app for testers without access to the signing machine.
- **Zero Pack Exposure:** The hosted function reads only public pack metadata; real pack binaries never touch the server.
- **Admin-Gated API:** `POST /api/issue` is protected by a constant-time-compared admin token; secrets live only in Vercel's encrypted environment variables.

## 📁 Project File & Folder Structure

```text
encore-license-generator/
├── api/
│   └── index.py            # Vercel serverless function (Flask): hosted UI + POST /api/issue
├── packs.json              # Public pack metadata (pack IDs, song counts, sizes)
├── tools/
│   ├── enclib_license.py   # CLI engine (keygen / issue / inspect / selftest)
│   ├── main.py             # Local-only web UI (thin wrapper around the CLI)
│   ├── ENCLIB_LICENSE.md   # Full manual: setup, issuing, revocation, security
│   └── keys/               # Signing private key (git-ignored, never committed)
├── vercel.json             # Deployment config (rewrites + Python runtime)
└── requirements.txt        # Flask + cryptography for the hosted function
```

## 📥 Installation

Prerequisites: Python 3.10+, Node.js (v18+, for Vercel deploys only).

```bash
# Clone the repository
git clone https://github.com/MACteaism/encore-license-generator.git

# Navigate to the project directory
cd encore-license-generator

# No third-party dependencies needed for the CLI and local UI
# (the hosted function uses Flask + cryptography, see requirements.txt)
```

## 🚀 Quick Start

```bash
# 1. Generate a signing key (once; back it up — losing it invalidates all future licenses)
python tools/enclib_license.py keygen

# 2. Verify the tooling
python tools/enclib_license.py selftest

# 3a. Issue a license from the CLI
python tools/enclib_license.py issue --activation ENCLIB-ACT-1:... --pack test-output\EncoreSongPack-102026.enclib --days 14

# 3b. Or run the local web UI (binds to 127.0.0.1 only)
python tools/main.py
```

**Hosted generator:** deployed at https://encore-license-generator.vercel.app via `npx vercel --prod`. Secrets (`ENCLIB_SIGNING_KEY`, `ENCLIB_ADMIN_TOKEN`, `ENCLIB_PASSPHRASE_<NAME>`) live in Vercel's encrypted environment variables — never in git.

## 🛠️ Tech Stack

- **CLI / Local UI:** Python 3.10+ standard library only (`cryptography` for ECDSA + RSA-OAEP)
- **Hosted Generator:** Flask on Vercel's Python serverless runtime
- **Crypto:** ECDSA P-256 signatures, RSA-OAEP passphrase wrapping, Argon2id pack KDF (on the app side)

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
