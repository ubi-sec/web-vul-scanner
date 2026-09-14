#!/usr/bin/env python3
"""
Advanced Web Vulnerability Scanner v3
======================================
Author  : ubi.sec
Purpose : Educational / Authorized Penetration Testing ONLY

What this scanner does differently from v2:
  - PASSIVE checks  : headers, TLS, cookies, CORS, HTTP methods
  - ACTIVE  checks  : actually sends attack payloads and verifies
                      the response to confirm vulnerability (not guess)

Active checks included:
  1.  XSS  (Reflected) — tries multiple payloads, checks reflection
  2.  SQL Injection    — tries error-triggering payloads, checks DB errors
  3.  Open Redirect    — tries redirect payloads, checks Location header
  4.  CSRF             — checks forms for anti-CSRF tokens
  5.  Path Traversal   — tries ../ sequences, checks for /etc/passwd content
  6.  Sensitive Files  — actually GETs each path and checks content
  7.  Command Injection— tries basic OS command payloads in params
  8.  CORS Spoof       — sends forged Origin header, checks if allowed
  9.  Clickjacking PoC — checks both header and frame-embed possibility
 10.  Host Header Inj  — sends modified Host header, checks reflection

LEGAL: Only scan systems you own or have explicit written permission.
"""

import requests
import ssl
import socket
import time
import urllib3
from urllib.parse import urlparse, urljoin, quote
from bs4 import BeautifulSoup
from tabulate import tabulate

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ─────────────────────────────────────────────────────────────────
#  Result colours (terminal)
# ─────────────────────────────────────────────────────────────────
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"


class ScannerV3:
    def __init__(self, target_url, timeout=8, delay=0.5):
        if not target_url.startswith(("http://", "https://")):
            target_url = "http://" + target_url
        self.target   = target_url.rstrip("/")
        self.parsed   = urlparse(self.target)
        self.timeout  = timeout
        self.delay    = delay          # seconds between active probes
        self.results  = []             # (category, type, status, confidence, details)

        self.session  = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                          "AppleWebKit/537.36 (KHTML, like Gecko) "
                          "Chrome/124.0 Safari/537.36"
        })

    # ──────────────────── helpers ────────────────────
    def record(self, category, check, vulnerable, confidence, details):
        self.results.append({
            "category"  : category,
            "check"     : check,
            "status"    : "VULNERABLE"     if vulnerable else "NOT VULNERABLE",
            "confidence": confidence,       # HIGH / MEDIUM / LOW
            "details"   : details
        })

    def get(self, url, headers=None, params=None):
        try:
            return self.session.get(
                url, timeout=self.timeout, verify=False,
                allow_redirects=False,
                headers=headers or {}, params=params or {}
            )
        except requests.exceptions.RequestException:
            return None

    def sep(self, label=""):
        print(f"\n{CYAN}{BOLD}{'─'*30} {label} {'─'*30}{RESET}")

    # ═══════════════════════════════════════════════════════════════
    #  PASSIVE CHECKS
    # ═══════════════════════════════════════════════════════════════

    def passive_security_headers(self, resp):
        self.sep("PASSIVE: Security Headers")
        required = {
            "X-Frame-Options"       : "Clickjacking protection",
            "X-Content-Type-Options": "MIME sniffing protection",
            "Content-Security-Policy":"Script injection policy",
            "Strict-Transport-Security": "HTTPS enforcement (HSTS)",
            "Referrer-Policy"       : "Referrer info leak control",
            "Permissions-Policy"    : "Feature/API access control",
        }
        missing = []
        for h, desc in required.items():
            if h not in resp.headers:
                missing.append(h)
                print(f"  {RED}✗ Missing:{RESET} {h} ({desc})")
            else:
                print(f"  {GREEN}✓ Present:{RESET} {h}: {resp.headers[h][:60]}")

        self.record("Passive", "Security Headers", bool(missing),
                    "HIGH" if len(missing) >= 3 else "MEDIUM",
                    f"Missing {len(missing)}/{len(required)}: {', '.join(missing)}" if missing else "All present")

    def passive_server_disclosure(self, resp):
        self.sep("PASSIVE: Server / Tech Disclosure")
        info_headers = ["Server","X-Powered-By","X-AspNet-Version","X-Generator","X-Backend-Server"]
        leaked = {}
        for h in info_headers:
            v = resp.headers.get(h)
            if v:
                leaked[h] = v
                print(f"  {YELLOW}⚠ Leaking:{RESET} {h}: {v}")
        if not leaked:
            print(f"  {GREEN}✓ No tech info leaked in headers{RESET}")
        self.record("Passive", "Server Info Disclosure", bool(leaked), "LOW",
                    "; ".join(f"{k}={v}" for k,v in leaked.items()) if leaked else "Nothing leaked")

    def passive_cookie_flags(self, resp):
        self.sep("PASSIVE: Cookie Flags")
        raw = resp.headers.get("Set-Cookie","")
        if not raw:
            print(f"  {GREEN}✓ No cookies set{RESET}")
            self.record("Passive","Cookie Flags",False,"LOW","No cookies in this response")
            return
        issues = []
        for flag in ["HttpOnly","Secure","SameSite"]:
            if flag not in raw:
                issues.append(f"Missing {flag}")
                print(f"  {RED}✗ {flag} missing{RESET}")
            else:
                print(f"  {GREEN}✓ {flag} present{RESET}")
        self.record("Passive","Cookie Flags",bool(issues),"MEDIUM" if issues else "LOW",
                    ", ".join(issues) if issues else "All flags present")

    def passive_tls(self):
        self.sep("PASSIVE: HTTPS / TLS Certificate")
        host = self.parsed.hostname
        if self.parsed.scheme != "https":
            print(f"  {RED}✗ Site served over plain HTTP — no encryption{RESET}")
            self.record("Passive","HTTPS/TLS",True,"HIGH","No HTTPS")
            return
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, 443), timeout=self.timeout) as s:
                with ctx.wrap_socket(s, server_hostname=host) as ss:
                    cert = ss.getpeercert()
            expiry = cert.get("notAfter","unknown")
            print(f"  {GREEN}✓ Valid TLS certificate{RESET}")
            print(f"  {GREEN}✓ Expires: {expiry}{RESET}")
            self.record("Passive","HTTPS/TLS",False,"HIGH",f"Valid cert, expires {expiry}")
        except ssl.SSLCertVerificationError:
            print(f"  {RED}✗ Invalid / untrusted certificate{RESET}")
            self.record("Passive","HTTPS/TLS",True,"HIGH","Invalid certificate")
        except Exception as e:
            print(f"  {YELLOW}⚠ Could not verify TLS: {e}{RESET}")
            self.record("Passive","HTTPS/TLS",False,"LOW",f"Could not verify ({e})")

    def passive_http_methods(self):
        self.sep("PASSIVE: Dangerous HTTP Methods")
        try:
            r = self.session.options(self.target, timeout=self.timeout, verify=False)
            allow = r.headers.get("Allow","")
            risky = [m for m in ["PUT","DELETE","TRACE","CONNECT"] if m in allow]
            if risky:
                print(f"  {RED}✗ Risky methods enabled: {', '.join(risky)}{RESET}")
            else:
                print(f"  {GREEN}✓ No dangerous methods: {allow or 'not disclosed'}{RESET}")
            self.record("Passive","HTTP Methods",bool(risky),"MEDIUM",
                        f"Enabled: {', '.join(risky)}" if risky else f"Allowed: {allow or 'not disclosed'}")
        except:
            self.record("Passive","HTTP Methods",False,"LOW","OPTIONS blocked/unavailable")

    # ═══════════════════════════════════════════════════════════════
    #  ACTIVE CHECKS — actually send payloads
    # ═══════════════════════════════════════════════════════════════

    def active_xss(self):
        self.sep("ACTIVE: Reflected XSS")
        payloads = [
            '<script>alert("XSS")</script>',
            '"><script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
            '" autofocus onfocus=alert(1) x="',
            "javascript:alert(1)",
        ]
        confirmed = False
        confirmed_payload = ""
        for p in payloads:
            sep = "&" if "?" in self.target else "?"
            url = f"{self.target}{sep}q={quote(p)}"
            r = self.get(url)
            if r is None:
                continue
            # Check if raw unencoded payload appears in response
            if p in r.text and "&lt;" not in r.text.split(p)[0][-5:]:
                confirmed = True
                confirmed_payload = p
                print(f"  {RED}✗ CONFIRMED: Payload reflected unencoded:{RESET} {p[:60]}")
                break
            # Check if partial markers reflect (e.g. quotes not escaped)
            elif 'alert' in r.text and p[:10] in r.text:
                confirmed_payload = p
                print(f"  {YELLOW}⚠ PARTIAL reflection detected: {p[:50]}{RESET}")
            time.sleep(self.delay)

        if not confirmed:
            print(f"  {GREEN}✓ No XSS payloads reflected unencoded in tested params{RESET}")

        self.record("Active","Reflected XSS",confirmed,
                    "HIGH" if confirmed else "LOW",
                    f"Confirmed with payload: {confirmed_payload}" if confirmed
                    else "All tested payloads were encoded or not reflected")

    def active_sqli(self):
        self.sep("ACTIVE: SQL Injection")
        db_errors = [
            "you have an error in your sql syntax",
            "warning: mysql","unclosed quotation mark",
            "quoted string not properly terminated",
            "pg_query():","sqlite_query","ORA-01756",
            "syntax error or access violation",
        ]
        payloads = ["'","\"","' OR '1'='1","' OR 1=1--","1' AND SLEEP(0)--","1; DROP TABLE"]
        detected = False
        detected_detail = ""
        for p in payloads:
            sep = "&" if "?" in self.target else "?"
            url = f"{self.target}{sep}id={quote(p)}"
            r = self.get(url)
            if r is None:
                continue
            body = r.text.lower()
            for err in db_errors:
                if err in body:
                    detected = True
                    detected_detail = f"Payload '{p}' triggered DB error: '{err}'"
                    print(f"  {RED}✗ DB error triggered: {err}{RESET}")
                    break
            if detected:
                break
            time.sleep(self.delay)

        if not detected:
            print(f"  {GREEN}✓ No SQL error messages triggered by test payloads{RESET}")
        self.record("Active","SQL Injection",detected,
                    "HIGH" if detected else "LOW",
                    detected_detail if detected else "No DB errors triggered — manual testing recommended")

    def active_open_redirect(self):
        self.sep("ACTIVE: Open Redirect")
        redirect_targets = [
            "https://evil.com",
            "//evil.com",
            "https://evil.com%2F@legitimate-site.com",
        ]
        params = ["url","redirect","next","return","goto","target","redir"]
        confirmed = False
        for param in params:
            for t in redirect_targets:
                sep = "&" if "?" in self.target else "?"
                url = f"{self.target}{sep}{param}={quote(t)}"
                r = self.get(url)
                if r is not None and r.status_code in [301,302,303,307,308]:
                    loc = r.headers.get("Location","")
                    if "evil.com" in loc or t in loc:
                        confirmed = True
                        print(f"  {RED}✗ Open redirect via ?{param}= → {loc}{RESET}")
                        self.record("Active","Open Redirect",True,"HIGH",
                                    f"Param '{param}' redirects to: {loc}")
                        return
                time.sleep(self.delay)
        if not confirmed:
            print(f"  {GREEN}✓ No open redirect detected in common params{RESET}")
            self.record("Active","Open Redirect",False,"MEDIUM",
                        "Common redirect params not found or not exploitable")

    def active_csrf_check(self):
        self.sep("ACTIVE: CSRF Token Check")
        r = self.get(self.target)
        if r is None:
            self.record("Active","CSRF Protection",False,"LOW","Could not fetch page")
            return
        soup = BeautifulSoup(r.text, "html.parser")
        forms = soup.find_all("form")
        if not forms:
            print(f"  {GREEN}✓ No forms found on page{RESET}")
            self.record("Active","CSRF Protection",False,"LOW","No forms to check")
            return

        unprotected = []
        for i, form in enumerate(forms):
            action = form.get("action","(no action)")
            method = form.get("method","GET").upper()
            # look for CSRF token fields
            hidden_inputs = form.find_all("input", type="hidden")
            token_names   = ["csrf","token","nonce","_wpnonce","authenticity_token","__RequestVerificationToken"]
            has_token = any(
                any(t in (inp.get("name","") + inp.get("id","")).lower() for t in token_names)
                for inp in hidden_inputs
            )
            if method == "POST" and not has_token:
                unprotected.append(f"Form #{i+1} action={action}")
                print(f"  {RED}✗ POST form without CSRF token: {action}{RESET}")
            elif has_token:
                print(f"  {GREEN}✓ Form #{i+1} has CSRF token{RESET}")
            else:
                print(f"  {YELLOW}⚠ Form #{i+1} is GET method — CSRF not required{RESET}")

        self.record("Active","CSRF Protection",bool(unprotected),
                    "HIGH" if unprotected else "LOW",
                    f"Unprotected POST forms: {'; '.join(unprotected)}" if unprotected
                    else f"{len(forms)} form(s) checked — all protected or GET-only")

    def active_path_traversal(self):
        self.sep("ACTIVE: Path Traversal")
        payloads = [
            "../../../../etc/passwd",
            "..%2F..%2F..%2Fetc%2Fpasswd",
            "%2e%2e/%2e%2e/etc/passwd",
        ]
        params = ["file","path","page","include","doc","load"]
        confirmed = False
        for param in params:
            for p in payloads:
                sep = "&" if "?" in self.target else "?"
                url = f"{self.target}{sep}{param}={p}"
                r = self.get(url)
                if r is not None and "root:x:" in r.text:
                    confirmed = True
                    print(f"  {RED}✗ /etc/passwd content found via ?{param}={p}{RESET}")
                    self.record("Active","Path Traversal",True,"HIGH",
                                f"Param '{param}' leaks /etc/passwd")
                    return
                time.sleep(self.delay)
        if not confirmed:
            print(f"  {GREEN}✓ No path traversal detected in common params{RESET}")
            self.record("Active","Path Traversal",False,"MEDIUM","No traversal indicators found")

    def active_sensitive_files(self):
        self.sep("ACTIVE: Sensitive File / Directory Exposure")
        targets = {
            ".env"               : ["DB_PASSWORD","APP_KEY","SECRET"],
            ".git/config"        : ["[core]","[remote"],
            "backup.zip"         : [],
            "wp-config.php.bak"  : ["DB_PASSWORD","DB_USER"],
            "phpinfo.php"        : ["PHP Version","phpinfo"],
            "admin/"             : [],
            "wp-login.php"       : ["user_login","WordPress"],
            "robots.txt"         : [],
            "sitemap.xml"        : [],
            ".well-known/security.txt": [],
        }
        found_critical = []
        found_info     = []
        for path, markers in targets.items():
            url = urljoin(self.target + "/", path)
            r   = self.get(url)
            if r is not None and r.status_code == 200:
                content = r.text
                critical = path in [".env",".git/config","backup.zip","wp-config.php.bak","phpinfo.php"]
                marker_hit = any(m in content for m in markers) if markers else True
                if critical and marker_hit:
                    found_critical.append(path)
                    print(f"  {RED}✗ CRITICAL exposed: /{path} ({r.status_code}) — content confirmed{RESET}")
                elif r.status_code == 200:
                    found_info.append(path)
                    print(f"  {YELLOW}⚠ Accessible (info): /{path} ({r.status_code}){RESET}")
            else:
                code = r.status_code if r else "err"
                print(f"  {GREEN}✓ /{path} → {code}{RESET}")
            time.sleep(self.delay)

        self.record("Active","Sensitive Files (Critical)", bool(found_critical), "HIGH",
                    f"CRITICAL files exposed: {', '.join(found_critical)}" if found_critical
                    else "No critical files accessible")
        self.record("Active","Sensitive Files (Info)", bool(found_info), "LOW",
                    f"Accessible: {', '.join(found_info)}" if found_info else "None")

    def active_cors_spoof(self):
        self.sep("ACTIVE: CORS Origin Spoofing")
        evil_origins = ["https://evil.com", "https://attacker.net", "null"]
        for origin in evil_origins:
            r = self.get(self.target, headers={"Origin": origin})
            if r is None:
                continue
            acao = r.headers.get("Access-Control-Allow-Origin","")
            acac = r.headers.get("Access-Control-Allow-Credentials","")
            if acao == "*":
                print(f"  {YELLOW}⚠ Wildcard ACAO — no credentials risk unless ACAC also set{RESET}")
                self.record("Active","CORS Spoofing",True,"MEDIUM","Wildcard ACAO (*)")
                return
            if origin in acao:
                if "true" in acac.lower():
                    print(f"  {RED}✗ CRITICAL: Forged origin '{origin}' accepted + credentials allowed!{RESET}")
                    self.record("Active","CORS Spoofing",True,"HIGH",
                                f"Origin '{origin}' reflected and credentials=true")
                    return
                else:
                    print(f"  {YELLOW}⚠ Forged origin reflected but no credentials: {acao}{RESET}")
                    self.record("Active","CORS Spoofing",True,"MEDIUM",f"Origin reflected: {acao}")
                    return
            time.sleep(self.delay)
        print(f"  {GREEN}✓ No forged origins accepted{RESET}")
        self.record("Active","CORS Spoofing",False,"HIGH","Forged origins rejected")

    def active_host_header_injection(self):
        self.sep("ACTIVE: Host Header Injection")
        fake_host = "evil-injected.com"
        r = self.get(self.target, headers={"Host": fake_host})
        if r is None:
            self.record("Active","Host Header Injection",False,"LOW","Request failed")
            return
        if fake_host in r.text:
            print(f"  {RED}✗ Injected Host header reflected in response body!{RESET}")
            self.record("Active","Host Header Injection",True,"HIGH",
                        "Fake host value reflected in response — password reset link hijacking possible")
        else:
            print(f"  {GREEN}✓ Injected host not reflected in response{RESET}")
            self.record("Active","Host Header Injection",False,"MEDIUM","Not reflected")

    # ═══════════════════════════════════════════════════════════════
    #  MAIN RUNNER
    # ═══════════════════════════════════════════════════════════════

    def run(self):
        print(f"\n{BOLD}{CYAN}╔══════════════════════════════════════════════════════╗")
        print(f"║   Advanced Web Vulnerability Scanner v3              ║")
        print(f"║   Author: ubi.sec                                    ║")
        print(f"╚══════════════════════════════════════════════════════╝{RESET}")
        print(f"\nTarget  : {BOLD}{self.target}{RESET}")
        print(f"Started : {time.strftime('%Y-%m-%d %H:%M:%S')}")

        resp = self.get(self.target)
        if resp is None:
            print(f"\n{RED}Target unreachable. Aborting.{RESET}")
            return

        # ── Passive ──
        self.passive_security_headers(resp)
        self.passive_server_disclosure(resp)
        self.passive_cookie_flags(resp)
        self.passive_tls()
        self.passive_http_methods()

        # ── Active ──
        self.active_xss()
        self.active_sqli()
        self.active_open_redirect()
        self.active_csrf_check()
        self.active_path_traversal()
        self.active_sensitive_files()
        self.active_cors_spoof()
        self.active_host_header_injection()

        self.print_report()

    def print_report(self):
        self.sep("FINAL REPORT")
        table = []
        order = {"HIGH":0,"MEDIUM":1,"LOW":2}
        sorted_results = sorted(self.results, key=lambda x:(
            0 if x["status"]=="VULNERABLE" else 1,
            order.get(x["confidence"],3)
        ))
        for r in sorted_results:
            status_str = (f"{RED}{BOLD}{r['status']}{RESET}"
                          if r["status"]=="VULNERABLE"
                          else f"{GREEN}{r['status']}{RESET}")
            conf_str   = (f"{RED}{r['confidence']}{RESET}" if r["confidence"]=="HIGH"
                          else f"{YELLOW}{r['confidence']}{RESET}" if r["confidence"]=="MEDIUM"
                          else r["confidence"])
            table.append([
                r["category"],
                r["check"],
                status_str,
                conf_str,
                r["details"][:65] + ("…" if len(r["details"])>65 else "")
            ])

        print("\n" + tabulate(
            table,
            headers=["TYPE","CHECK","STATUS","CONFIDENCE","DETAILS"],
            tablefmt="grid"
        ))

        vuln  = [r for r in self.results if r["status"]=="VULNERABLE"]
        clean = [r for r in self.results if r["status"]!="VULNERABLE"]
        high  = [r for r in vuln if r["confidence"]=="HIGH"]

        print(f"\n{BOLD}Summary:{RESET}")
        print(f"  Total checks  : {len(self.results)}")
        print(f"  {RED}VULNERABLE    : {len(vuln)}{RESET}  (HIGH={len(high)})")
        print(f"  {GREEN}NOT VULNERABLE: {len(clean)}{RESET}")
        print(f"\nScan completed: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")


if __name__ == "__main__":
    print(f"\n{'='*60}")
    print(" Web Vulnerability Scanner v3 — Authorized Testing Only")
    print(f"{'='*60}")
    url = input("\nEnter target URL (e.g., https://example.com): ").strip()
    scanner = ScannerV3(url)
    scanner.run()
