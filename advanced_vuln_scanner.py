#!/usr/bin/env python3
"""
Advanced Web Vulnerability Scanner (v2)
-----------------------------------------
Ek URL leta hai, usko multiple vulnerability checks se guzaarta hai,
aur result ko ek clean "chart sheet" (table) format mein deta hai:

    VULNERABILITY          STATUS              DETAILS
    ----------------------------------------------------------------
    Missing Security Hdrs  VULNERABLE          4 headers missing
    HTTPS/TLS              NOT VULNERABLE      Valid certificate
    ...

IMPORTANT: Sirf apni owned website ya jahan explicit written
authorization ho, wahi is script ko run karein.
"""

import requests
import ssl
import socket
import urllib3
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from tabulate import tabulate

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class AdvancedVulnScanner:
    def __init__(self, target_url, timeout=6):
        if not target_url.startswith(("http://", "https://")):
            target_url = "http://" + target_url
        self.target_url = target_url.rstrip("/")
        self.parsed = urlparse(self.target_url)
        self.timeout = timeout
        self.results = []   # list of dicts: {check, status, details}
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                          "AppleWebKit/537.36 (KHTML, like Gecko) "
                          "Chrome/120.0 Safari/537.36"
        })

    # ---------------- helper ----------------
    def record(self, check_name, vulnerable, details):
        self.results.append({
            "check": check_name,
            "status": "VULNERABLE" if vulnerable else "NOT VULNERABLE",
            "details": details
        })

    def safe_get(self, url, **kwargs):
        try:
            return self.session.get(url, timeout=self.timeout, verify=False, **kwargs)
        except requests.exceptions.RequestException as e:
            return None

    # ---------------- individual checks ----------------
    def check_security_headers(self, resp):
        required = [
            "X-Frame-Options", "X-Content-Type-Options",
            "Content-Security-Policy", "Strict-Transport-Security",
            "Referrer-Policy", "Permissions-Policy"
        ]
        missing = [h for h in required if h not in resp.headers]
        self.record(
            "Missing Security Headers",
            vulnerable=bool(missing),
            details=f"Missing: {', '.join(missing)}" if missing else "All key headers present"
        )

    def check_server_disclosure(self, resp):
        leaked = []
        for h in ["Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"]:
            v = resp.headers.get(h)
            if v:
                leaked.append(f"{h}: {v}")
        self.record(
            "Server / Tech Info Disclosure",
            vulnerable=bool(leaked),
            details="; ".join(leaked) if leaked else "No version/tech info leaked"
        )

    def check_cookie_flags(self, resp):
        cookie = resp.headers.get("Set-Cookie")
        if not cookie:
            self.record("Cookie Security Flags", vulnerable=False, details="No cookies set on this response")
            return
        issues = []
        if "HttpOnly" not in cookie:
            issues.append("Missing HttpOnly")
        if "Secure" not in cookie:
            issues.append("Missing Secure")
        if "SameSite" not in cookie:
            issues.append("Missing SameSite")
        self.record(
            "Cookie Security Flags",
            vulnerable=bool(issues),
            details=", ".join(issues) if issues else "HttpOnly, Secure, SameSite all present"
        )

    def check_https_tls(self):
        host = self.parsed.hostname
        if self.parsed.scheme != "https":
            self.record("HTTPS / TLS Enforcement", vulnerable=True, details="Site served over plain HTTP")
            return
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, 443), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    expiry = cert.get("notAfter", "unknown")
            self.record("HTTPS / TLS Enforcement", vulnerable=False,
                        details=f"Valid certificate, expires {expiry}")
        except ssl.SSLCertVerificationError:
            self.record("HTTPS / TLS Enforcement", vulnerable=True, details="Invalid/untrusted certificate")
        except Exception as e:
            self.record("HTTPS / TLS Enforcement", vulnerable=True, details=f"Could not verify ({e})")

    def check_clickjacking(self, resp):
        xfo = resp.headers.get("X-Frame-Options")
        csp = resp.headers.get("Content-Security-Policy", "")
        vulnerable = not xfo and "frame-ancestors" not in csp
        self.record(
            "Clickjacking (iframe embedding)",
            vulnerable=vulnerable,
            details="No X-Frame-Options/CSP frame-ancestors" if vulnerable else "Protected"
        )

    def check_cors(self, resp):
        acao = resp.headers.get("Access-Control-Allow-Origin")
        vulnerable = acao == "*"
        self.record(
            "CORS Misconfiguration",
            vulnerable=vulnerable,
            details=f"Access-Control-Allow-Origin: {acao}" if acao else "No CORS header exposed"
        )

    def check_http_methods(self):
        try:
            resp = self.session.options(self.target_url, timeout=self.timeout, verify=False)
            allow = resp.headers.get("Allow", "")
            risky = [m for m in ["PUT", "DELETE", "TRACE", "CONNECT"] if m in allow]
            self.record(
                "Dangerous HTTP Methods",
                vulnerable=bool(risky),
                details=f"Enabled: {', '.join(risky)}" if risky else f"Allowed: {allow or 'not disclosed'}"
            )
        except requests.exceptions.RequestException:
            self.record("Dangerous HTTP Methods", vulnerable=False, details="Could not determine (OPTIONS blocked)")

    def check_exposed_paths(self):
        sensitive = [".env", ".git/config", "backup.zip", "config.php.bak", "wp-config.php.bak"]
        found = []
        for path in sensitive:
            r = self.safe_get(urljoin(self.target_url + "/", path))
            if r is not None and r.status_code == 200:
                found.append(path)
        self.record(
            "Exposed Sensitive Files",
            vulnerable=bool(found),
            details=f"Accessible: {', '.join(found)}" if found else "None of the tested sensitive files were exposed"
        )

    def check_reflected_input(self, resp_body_check_url):
        marker = "vsCHK9981"
        sep = "&" if "?" in self.target_url else "?"
        test_url = f"{self.target_url}{sep}q={marker}"
        r = self.safe_get(test_url)
        if r is None:
            self.record("Reflected Input (possible XSS)", vulnerable=False, details="Could not test (request failed)")
            return
        vulnerable = marker in r.text
        self.record(
            "Reflected Input (possible XSS)",
            vulnerable=vulnerable,
            details="Input reflected unmodified — needs manual confirmation" if vulnerable
                    else "No reflection detected on tested parameter"
        )

    def check_directory_listing(self):
        r = self.safe_get(self.target_url + "/")
        vulnerable = False
        if r is not None and ("Index of /" in r.text or "Directory Listing" in r.text):
            vulnerable = True
        self.record(
            "Directory Listing Enabled",
            vulnerable=vulnerable,
            details="Server exposes directory listing" if vulnerable else "Not detected"
        )

    def check_forms_presence(self, resp):
        soup = BeautifulSoup(resp.text, "html.parser")
        forms = soup.find_all("form")
        self.record(
            "Forms Present (manual review needed)",
            vulnerable=bool(forms),
            details=f"{len(forms)} form(s) found — check manually for SQLi/XSS/CSRF" if forms else "No forms found"
        )

    # ---------------- runner ----------------
    def run_scan(self):
        print(f"\nScanning target: {self.target_url}")
        print("=" * 70)
        resp = self.safe_get(self.target_url)
        if resp is None:
            print("Target unreachable — aborting scan.")
            return

        self.check_security_headers(resp)
        self.check_server_disclosure(resp)
        self.check_cookie_flags(resp)
        self.check_https_tls()
        self.check_clickjacking(resp)
        self.check_cors(resp)
        self.check_http_methods()
        self.check_exposed_paths()
        self.check_reflected_input(resp)
        self.check_directory_listing()
        self.check_forms_presence(resp)

        self.print_chart()

    def print_chart(self):
        table_data = []
        vuln_count = 0
        for r in self.results:
            if r["status"] == "VULNERABLE":
                vuln_count += 1
            table_data.append([r["check"], r["status"], r["details"]])

        print("\n" + tabulate(
            table_data,
            headers=["VULNERABILITY CHECK", "STATUS", "DETAILS"],
            tablefmt="grid"
        ))

        print(f"\nTotal checks run: {len(self.results)}")
        print(f"Vulnerable findings: {vuln_count}")
        print(f"Clean findings: {len(self.results) - vuln_count}\n")


if __name__ == "__main__":
    print("=== Advanced Web Vulnerability Scanner (Educational / Authorized Use Only) ===")
    print("Only scan systems you own or have explicit written permission to test.\n")
    url = input("Enter target URL (e.g., https://example.com): ").strip()
    scanner = AdvancedVulnScanner(url)
    scanner.run_scan()
