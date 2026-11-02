# PortScanner

A simple Python port scanner built with [python-nmap](https://pypi.org/project/python-nmap/).

## Requirements

- Python 3
- [Nmap](https://nmap.org/download.html) installed and available on the system PATH
- `python-nmap` package:

```bash
pip install python-nmap
```

## Usage

```bash
python scanner.py
```

The program will ask for:
1. The IP or domain to scan
2. The port or port range to scan (e.g. `80` or `1-1024`)
3. The nmap flags to use (e.g. `-sV`, `-O`, `-A`)
