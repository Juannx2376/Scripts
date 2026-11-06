# Scripts

A personal collection of Python scripts for learning network security, reconnaissance, and penetration testing concepts.

> ⚠️ **Ethical use only.** These tools are for education, CTFs, and authorized security testing. Only run them against networks, hosts, and systems that you own or have explicit permission to test. Misuse may be illegal.

## Contents

### PortScanner
A simple port scanner built with [python-nmap](https://pypi.org/project/python-nmap/).

Requirements: Python 3, [Nmap](https://nmap.org/download.html) on the system PATH, and `pip install python-nmap`.

```bash
cd PortScanner
python scanner.py
```

### Reverse Shell
A minimal educational reverse shell (a `listener.py` that runs on the attacker machine and a `client.py` that connects back). Standard library only.

```bash
# On the listening machine
python listener.py

# On the connecting machine
python client.py
```

### Escalada de Privilegios (Privilege Escalation)
Small Linux enumeration helpers, such as finding SUID binaries — a classic privilege-escalation enumeration step.

```bash
python "Escalada de Privilegios/Linux/escalada.py"
```

### Password Manager
A command-line password manager with real encryption (PBKDF2 + Fernet). Stores passwords encrypted in an auto-generated vault, protected by a master password that is never saved anywhere. Requires `pip install cryptography`.

```bash
cd "Password Manager"
python password_manager.py
```

### File Encryptor
A command-line tool to encrypt/decrypt any file with a password (PBKDF2 + Fernet, per-file salt). Produces a `.enc` file that can only be restored with the correct password. Requires `pip install cryptography`.

```bash
cd "File Encryption"
python file_encryption.py
```

### OSINT Tool
A domain reconnaissance tool that collects public information: IP resolution, DNS records (MX/TXT/NS/A/AAAA), subdomain discovery, HTTP headers, and WHOIS. Requires `pip install dnspython requests python-whois`.

```bash
cd "OSINT Tool"
python osint_tool.py
```

### Steganography Tool
Hide secret text messages inside images using LSB (Least Significant Bit) steganography — invisible to the eye. Also reveals hidden messages. Requires `pip install Pillow`.

```bash
cd Esteganografia
python esteganografia.py
```

### Encrypted Chat
A client/server chat with end-to-end encryption (sockets + threading + Fernet). Messages travel as ciphertext; both peers derive the key from a shared password. Requires `pip install cryptography`.

```bash
cd "Chat Cifrado"
python chat_cifrado.py
```

### Hash Cracker
A hash identifier + dictionary-attack cracker (MD5/SHA1/SHA256/SHA512). Identifies the hash type and brute-forces it against a wordlist. Standard library only.

```bash
cd "Hash Cracker"
python hash_cracker.py
```

### 2FA TOTP Generator
A time-based one-time password generator (RFC 6238) — the same 6-digit codes as Google Authenticator, with a live countdown. Verified against the official test vectors. Standard library only.

```bash
cd "2FA TOTP"
python 2fa_totp.py
```

### Log Analyzer
Scans SSH-style auth logs and detects brute-force attacks — IPs with many failed logins over a threshold. Regex + `Counter`; includes a sample log. The defensive/blue-team side. Standard library only.

```bash
cd "Log Analyzer"
python log_analyzer.py
```

## Requirements

- Python 3
- Most scripts use only the standard library. `PortScanner` additionally needs Nmap + `python-nmap`.

## License

Provided as-is for educational purposes.
