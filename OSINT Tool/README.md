# OSINT Tool

A command-line reconnaissance tool that gathers **public** information about a domain (OSINT = Open Source Intelligence). Nothing intrusive — just queries anyone can run.

> ⚠️ For education and authorized security testing only. Only investigate domains you own or have permission to analyze.

## Features

- 🌐 **Resolve IP** — resolve a domain to its IP address
- 📡 **DNS records** — MX, TXT, NS, A, AAAA (mail servers, SPF, nameservers…)
- 🔎 **Subdomain discovery** — brute-forces a list of common subdomain names
- 📋 **HTTP headers** — server software, technologies, security headers, cookies
- 🏢 **WHOIS** — registrar, creation/expiration dates, country, nameservers
- 🚀 **Full analysis** — runs all of the above on one domain at once

## Requirements

- Python 3
- Dependencies:

```bash
pip install dnspython requests python-whois
```

## Usage

```bash
python osint_tool.py
```

Pick an option from the menu and enter a domain (e.g. `github.com`). Option 6 runs the full analysis.

## Example

```
github.com -> 140.82.114.4

[MX]
    0 github-com.mail.protection.outlook.com.
[NS]
    dns1.p08.nsone.net.
    ...

Buscando subdominios de github.com...
    www.github.com -> 140.82.112.3
    admin.github.com -> 20.9.125.224
```
