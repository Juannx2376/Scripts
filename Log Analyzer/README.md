# Log Analyzer

A command-line tool that scans authentication logs (SSH-style) and **detects brute-force attacks** — IP addresses with many failed login attempts. The defensive / blue-team side of security.

## Features

- 🔎 Parses log lines with regex to extract failed-login IPs
- 📊 Counts failed attempts per IP (`collections.Counter`)
- 🚨 Flags IPs that exceed a configurable threshold as suspected attacks
- 🧾 Prints a clean report (total failures, unique IPs, alerts)
- ✅ Ignores successful logins — only failures count

## Requirements

- Python 3 (standard library only — `re`, `collections`)

## Usage

```bash
python log_analyzer.py
```

Enter the path to a log file and an alert threshold (press Enter for the default, 10). A sample log is included:

```
Ruta del archivo de log: sample_auth.log
Umbral de alerta (enter = 10): 
```

## Example output

```
Total de intentos fallidos: 27
IPs unicas con fallos     : 5
Umbral de alerta          : 10 intentos

2 IP(s) Sospechosa(s) de ataque:
    [Alerta] 185.220.101.47 -> 13 intentos fallidos
    [Alerta] 45.33.32.156 -> 11 intentos fallidos
```

## How it works

For each log line, a regex pulls the IP out of `Failed password ... from <IP>` entries. The counts are tallied per IP, and any IP at or above the threshold is reported as a likely brute-force attack. This is a small version of what SIEM / intrusion-detection tools do with auth logs.

> For education and authorized use only.
