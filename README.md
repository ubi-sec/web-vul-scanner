# Web Vulnerability Scanner

A lightweight Python tool that scans a given URL for common, easily-detectable
web security misconfigurations and presents the results in a clean,
tabular "chart sheet" format.

## ⚠️ Legal Disclaimer

**This tool is intended for educational purposes and authorized security
testing only.**

Only run this scanner against:
- Websites/applications that you personally own, **or**
- Systems for which you have explicit, written authorization to test

Scanning systems without permission may violate computer misuse laws
(e.g., the Computer Fraud and Abuse Act in the US, PECA 2016 in Pakistan,
and similar laws elsewhere). The author accepts no liability for misuse
of this tool.

## Features

This scanner checks for:

- Missing security headers (CSP, HSTS, X-Frame-Options, etc.)
- Server / technology information disclosure
- Cookie security flags (HttpOnly, Secure, SameSite)
- HTTPS / TLS certificate validity
- Clickjacking protection (iframe embedding)
- CORS misconfiguration
- Dangerous HTTP methods (PUT, DELETE, TRACE)
- Exposed sensitive files (`.env`, `.git/config`, backups)
- Reflected input (potential XSS indicator)
- Directory listing exposure
- Forms present on the page (flagged for manual review)

Results are printed as a table showing each check, whether it is
**VULNERABLE** or **NOT VULNERABLE**, and supporting details.

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/<your-username>/web-vuln-scanner.git
cd web-vuln-scanner
```

### 2. Install dependencies

**Option A — using a virtual environment (recommended):**

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

**Option B — Kali Linux / Debian system packages:**

```bash
sudo apt install python3-requests python3-bs4
pip3 install tabulate --break-system-packages
```

## Usage

Run the scanner and enter a target URL when prompted:

```bash
python3 advanced_vuln_scanner.py
```

Example:

```
=== Advanced Web Vulnerability Scanner (Educational / Authorized Use Only) ===
Only scan systems you own or have explicit written permission to test.

Enter target URL (e.g., https://example.com): https://your-own-site.com
```

The tool will scan the target and print a table like:

```
+--------------------------------+----------------+--------------------------------------+
| VULNERABILITY CHECK             | STATUS         | DETAILS                              |
+==================================+================+========================================+
| Missing Security Headers        | VULNERABLE     | Missing: X-Frame-Options, CSP...     |
| HTTPS / TLS Enforcement         | NOT VULNERABLE | Valid certificate, expires ...       |
+--------------------------------+----------------+--------------------------------------+
```

## Project Structure

```
web-vuln-scanner/
├── advanced_vuln_scanner.py   # Main scanner script
├── requirements.txt           # Python dependencies
├── README.md                  # This file
└── LICENSE                    # MIT License
```

## Contributing

Pull requests are welcome. For major changes, please open an issue first
to discuss what you would like to change.

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE)
file for details.
