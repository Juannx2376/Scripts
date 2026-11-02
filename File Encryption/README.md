# File Encryptor

Encrypt and decrypt any file with a password, from the command line.

Each file is encrypted with **Fernet** (AES) using a key derived from your password via **PBKDF2-HMAC-SHA256** (200,000 iterations). A fresh random **salt** is generated per file and stored in the first 16 bytes of the `.enc` output, so the same key can be re-derived on decryption. Without the correct password the file cannot be recovered.

## Features

- 🔒 Encrypt any file (text, images, PDFs, anything — works on raw bytes)
- 🔓 Decrypt back to the exact original
- 🧂 Per-file random salt stored inside the `.enc` file
- 🙈 Password entry hidden from the screen (`getpass`)
- ✅ Wrong password → decryption fails safely (`InvalidToken`)

## Requirements

- Python 3
- [`cryptography`](https://pypi.org/project/cryptography/):

```bash
pip install cryptography
```

## Usage

```bash
python file_encryption.py
```

Then choose an option:
- **Encrypt** → give the path of a file; it produces `<file>.enc`
- **Decrypt** → give the path of a `.enc` file; it restores the original

## How it works

```
encrypt:  password + random salt --PBKDF2--> key --Fernet--> ciphertext
          output file = [ salt (16 bytes) ][ ciphertext ]

decrypt:  read salt (first 16 bytes) + password --PBKDF2--> same key --> original
```

The salt is not secret — it only makes the key unique per file. The password is the secret, and it is never stored anywhere.
