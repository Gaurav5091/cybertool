from config import SQL_PAYLOADS, XSS_PAYLOADS, CSRF_PAYLOAD, REDIRECT_PAYLOADS, WEAK_PASSWORDS
from utils.http_utils import HTTPUtils
import re

class OWASPScanner:
    def __init__(self, target_url, advanced=False):
        self.target = target_url.rstrip('/')
        self.vulnerabilities = []
        self.advanced = advanced

    def check_sql_injection(self):
        """A1: Injection"""
        for payload in SQL_PAYLOADS:
            response = HTTPUtils.send_request(self.target, payload, advanced=self.advanced)
            if response and ("sql" in response.text.lower() or "error" in response.text.lower() or 
                             re.search(r"mysql|sqlite|postgres", response.text, re.I)):
                self.vulnerabilities.append(f"A1: SQL Injection possible with payload: {payload}")
            if self.advanced:
                response = HTTPUtils.send_request(self.target, payload, method="POST", advanced=True)
                if response and "error" in response.text.lower():
                    self.vulnerabilities.append(f"A1: SQL Injection (POST) possible with payload: {payload}")

    def check_broken_auth(self):
        """A2: Broken Authentication"""
        endpoints = [f"{self.target}/login", f"{self.target}/admin"]
        for url in endpoints:
            response = HTTPUtils.send_request(url)
            if response and response.status_code == 200 and "login" not in response.text.lower():
                self.vulnerabilities.append(f"A2: Potential unprotected endpoint: {url}")
            if self.advanced:
                for pwd in WEAK_PASSWORDS:
                    response = HTTPUtils.send_request(url, method="POST", data={"username": "admin", "password": pwd})
                    if response and "welcome" in response.text.lower():
                        self.vulnerabilities.append(f"A2: Weak password '{pwd}' accepted at {url}")

    def check_sensitive_data(self):
        """A3: Sensitive Data Exposure"""
        response = HTTPUtils.send_request(self.target, advanced=self.advanced)
        headers = HTTPUtils.get_headers(response)
        if response and ("password" in response.text.lower() or "credit card" in response.text.lower()):
            self.vulnerabilities.append("A3: Sensitive data exposed in response")
        if "Strict-Transport-Security" not in headers:
            self.vulnerabilities.append("A3: Missing HSTS header")
        if self.advanced and "X-Content-Type-Options" not in headers:
            self.vulnerabilities.append("A3: Missing X-Content-Type-Options header")

    def check_xml_external(self):
        """A4: XML External Entities (XXE)"""
        xxe_payload = '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'
        response = HTTPUtils.send_request(self.target, method="POST", data={"xml": xxe_payload}, 
                                         headers={"Content-Type": "application/xml"}, advanced=self.advanced)
        if response and "root:" in response.text:
            self.vulnerabilities.append("A4: XXE vulnerability detected")

    def check_broken_access(self):
        """A5: Broken Access Control"""
        response = HTTPUtils.send_request(f"{self.target}/admin", advanced=self.advanced)
        if response and response.status_code == 200:
            self.vulnerabilities.append("A5: Unrestricted access to /admin")
        if self.advanced:
            response = HTTPUtils.send_request(f"{self.target}?id=1")
            if response and HTTPUtils.send_request(f"{self.target}?id=2").text == response.text:
                self.vulnerabilities.append("A5: Possible IDOR vulnerability")

    def check_security_misconfig(self):
        """A6: Security Misconfiguration"""
        response = HTTPUtils.send_request(f"{self.target}/.git", advanced=self.advanced)
        if response and response.status_code == 200:
            self.vulnerabilities.append("A6: Exposed .git directory")
        if self.advanced:
            response = HTTPUtils.send_request(f"{self.target}/phpinfo.php")
            if response and "php" in response.text.lower():
                self.vulnerabilities.append("A6: Exposed phpinfo()")

    def check_xss(self):
        """A7: Cross-Site Scripting (XSS)"""
        for payload in XSS_PAYLOADS:
            response = HTTPUtils.send_request(self.target, payload, advanced=self.advanced)
            if response and payload in response.text:
                self.vulnerabilities.append(f"A7: XSS vulnerability with payload: {payload}")
            if self.advanced:
                response = HTTPUtils.send_request(self.target, method="POST", data={"input": payload})
                if response and payload in response.text:
                    self.vulnerabilities.append(f"A7: XSS (POST) with payload: {payload}")

    def check_insecure_deserialization(self):
        """A8: Insecure Deserialization"""
        payload = "O:4:\"Test\":1:{s:4:\"data\";s:10:\"malicious\"}"
        response = HTTPUtils.send_request(self.target, method="POST", data={"data": payload}, advanced=self.advanced)
        if response and "malicious" in response.text:
            self.vulnerabilities.append("A8: Possible insecure deserialization")

    def check_components_vuln(self):
        """A9: Using Components with Known Vulnerabilities"""
        response = HTTPUtils.send_request(self.target, advanced=self.advanced)
        headers = HTTPUtils.get_headers(response)
        if "Server" in headers and "Apache/2.2" in headers["Server"]:
            self.vulnerabilities.append("A9: Outdated server software detected")
        if self.advanced and "X-Powered-By" in headers and "PHP/5." in headers["X-Powered-By"]:
            self.vulnerabilities.append("A9: Outdated PHP version detected")

    def check_unvalidated_redirects(self):
        """A10: Insufficient Logging & Monitoring (Redirects here for simplicity)"""
        for payload in REDIRECT_PAYLOADS:
            response = HTTPUtils.send_request(f"{self.target}?redirect={payload}", advanced=self.advanced)
            if response and response.url.startswith(payload):
                self.vulnerabilities.append(f"A10: Unvalidated redirect to {payload}")

    def scan(self):
        """Run all OWASP Top 10 checks"""
        print(f"[*] Scanning {self.target} {'(Advanced Mode)' if self.advanced else ''}...")
        self.check_sql_injection()
        self.check_broken_auth()
        self.check_sensitive_data()
        self.check_xml_external()
        self.check_broken_access()
        self.check_security_misconfig()
        self.check_xss()
        self.check_insecure_deserialization()
        self.check_components_vuln()
        self.check_unvalidated_redirects()
        return self.vulnerabilities
