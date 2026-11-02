# Password Manager

A command-line password manager with real encryption, built in Python.

Passwords are encrypted with **Fernet** (AES) using a key derived from a master password via **PBKDF2-HMAC-SHA256** (200,000 iterations + random salt). The master password is never stored anywhere — if you lose it, the vault cannot be recovered. That is by design: it's what guarantees no one (not even the program) can read your passwords without it.

## Features

- 🔐 Real encryption (PBKDF2 key derivation + Fernet symmetric encryption)
- 📁 Auto-generated vault folder (`~/.password_manager/`)
- 💾 Save passwords per service
- 🎲 Generate strong random passwords (and optionally store them)
- 👁️ View / decrypt a stored password
- 📋 List saved services
- 🛡️ Graceful error handling (wrong master password, unknown service)

## Requirements

- Python 3
- [`cryptography`](https://pypi.org/project/cryptography/):

```bash
pip install cryptography
```

## Usage

```bash
python password_manager.py
```

Follow the menu to save, generate, view, or list passwords. On first run, a salt and an empty vault are created automatically in your home folder.

> ⚠️ The vault (`~/.password_manager/`) is stored only on your machine and is **never** committed to this repository. Back up your master password — there is no recovery.

## How it works

1. You enter a **master password**.
2. PBKDF2 stretches it (200k rounds of SHA-256) with a stored random salt to derive a 32-byte key.
3. That key feeds a Fernet cipher that encrypts/decrypts each password.
4. Encrypted passwords are stored as a JSON map `{service: token}` in the vault folder.
