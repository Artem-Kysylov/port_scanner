# Multi-Threaded Port & Banner Scanner (`port_scanner.py`)

A fast, zero-dependency TCP port scanner and service banner grabber written in Python. Built for security reconnaissance, attack surface auditing, and service fingerprinting using `socket` and `concurrent.futures`.

## Features

- **Concurrent TCP Connect Scanning:** Uses `ThreadPoolExecutor` (50 parallel workers by default) to scan critical infrastructure ports in ~1 second without blocking on filtered ports.
- **Dual-Mode Banner Grabbing:** Automatically reads initial greetings from chatty services (SSH, FTP, SMTP) and sends lightweight `HEAD` probes to silent HTTP services (`80`, `3000`, `5000`, `8000`, `8080`, `8443`) to extract `Server` headers.
- **High-Value Port Checklist:** Targets 20 critical ports covering remote access (`21`, `22`, `3389`), databases (`3306`, `5432`, `6379`, `27017`), and exposed development servers (`3000`, `5000`, `8080`).
- **Zero External Dependencies:** Built 100% on the Python 3.9+ standard library (`socket`, `concurrent.futures`, `dataclasses`).
- **Input Sanitization:** Automatically strips protocols (`http://`, `https://`), paths, and port suffixes from target arguments.

## Requirements

- Python 3.9+ (no third-party packages required)

## Usage

Run against the default authorized test target (`scanme.nmap.org`):

```bash
python3 port_scanner.py
```

Scan a specific domain or IP address:

```bash
python3 port_scanner.py example.com
```

Scan multiple targets in one run:

```bash
python3 port_scanner.py scanme.nmap.org 192.168.1.1
```

## Example Output

```text
[*] Scanning 20 critical ports on scanme.nmap.org (45.33.32.156)...
============================================================================
Target: scanme.nmap.org (45.33.32.156) | Open Ports: 2 | Time: 1.00s
============================================================================
  22/tcp OPEN      SSH                -> SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13
  80/tcp OPEN      HTTP               -> Server: Apache/2.4.7 (Ubuntu)
```

## Disclaimer

This tool is created for educational purposes and authorized security testing only. Never scan networks or servers without explicit permission from the owner.

## Author

**Artem Kysylov** — [Syntax Labs](https://syntaxlabsapp.com)