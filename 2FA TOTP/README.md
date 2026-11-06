# 2FA TOTP Generator

A command-line **TOTP** (Time-based One-Time Password) generator — the same 6-digit codes that Google Authenticator, Authy, and banking apps produce. Built from scratch following **RFC 6238**.

## How it works

Your phone and the server never talk to each other to agree on a code. They both share a **secret** and both know the **current time**, so they independently compute the same code. That's the whole trick.

```
counter = current_unix_time // 30          (a new value every 30 seconds)
hmac    = HMAC-SHA1(secret, counter)       (keyed hash)
code    = dynamic truncation of hmac -> 6 digits
```

Because the counter changes every 30 seconds, the code changes every 30 seconds.

## Features

- 🔢 Generates standard 6-digit TOTP codes
- ⏱️ Live display with a countdown until the next code
- 🔑 Accepts any base32 secret (compatible with real authenticator apps)
- ✅ Verified against the official RFC 6238 test vectors

## Requirements

- Python 3 (standard library only — `hmac`, `hashlib`, `base64`, `struct`, `time`)

## Usage

```bash
python 2fa_totp.py
```

Enter a base32 secret (or press Enter to use an example one). The code refreshes live with a countdown. Press `Ctrl+C` to exit.

## Note

This generates the codes. To use it as real 2FA, the same secret would be registered with a service that checks the codes — this project is the authenticator side, for learning how TOTP works under the hood.
