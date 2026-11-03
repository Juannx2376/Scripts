# Encrypted Chat

A client/server chat where messages are **end-to-end encrypted**. Anyone intercepting the network traffic only sees ciphertext.

Built with raw sockets + threading + Fernet encryption. Both peers derive the same key from a shared password (SHA-256 → Fernet key), so only people who know the password can read the conversation.

## Features

- 🔌 Client/server over TCP sockets
- 🧵 Threaded: send and receive messages at the same time
- 🔐 End-to-end encryption with Fernet (AES) from a shared password
- 💬 Simple menu: create a room (server) or join one (client)

## Requirements

- Python 3
- [`cryptography`](https://pypi.org/project/cryptography/):

```bash
pip install cryptography
```

## Usage

Run it on both machines:

```bash
python chat_cifrado.py
```

- One person picks **1 - Create room (server)** and shares their IP.
- The other picks **2 - Join room (client)** and enters that IP.
- **Both must type the same shared password** — it's what derives the encryption key.
- Type `salir` to leave.

On the same local network it works directly (default port `9999`). Across different networks you'd need to port-forward or expose port 9999.

## How it works

```
shared password --SHA256--> 32 bytes --base64--> same Fernet key on both sides

send:     text --Fernet.encrypt--> ciphertext --socket--> peer
receive:  (background thread) socket --> ciphertext --Fernet.decrypt--> text
```

> ⚠️ For education and authorized use only.
