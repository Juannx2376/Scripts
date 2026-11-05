# Hash Cracker

A command-line hash identifier and dictionary-attack cracker, for learning how password hashing works.

> ⚠️ For education, CTFs, and authorized security testing only. Only crack hashes you own or have permission to test.

## Features

- 🔎 **Identify** the hash type by length (MD5, SHA1, SHA256, SHA512)
- 🔓 **Dictionary attack** — hashes each candidate word and compares it to the target
- 📄 **Load a wordlist** from a file (e.g. `rockyou.txt`), or use the small built-in list
- 🧮 Supports MD5, SHA1, SHA256, SHA512

## Why it works this way

Hashes are **one-way** — you can't reverse a hash back into the original text. So cracking means **guessing**: hash a lot of common passwords and compare each result to the target hash. When they match, you've found the password. That's exactly how real tools like John the Ripper and hashcat work.

## Requirements

- Python 3 (uses only the standard library — `hashlib`)

## Usage

```bash
python hash_cracker.py
```

Enter the hash to crack, then a wordlist path (or press Enter to use the built-in common-password list).

## Example

```
Hash a crackear: 4d186321c1a7f0f354b297e8914ab240
El hash parece ser MD5 longitud 32
Probando 10 palabras...
Encontrado: La contraseña es: hola
```
