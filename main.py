#!/usr/bin/env python3
"""
CyberTool - A Penetration Testing Automation Framework
Author: Gaurav Kumar
GitHub: https://github.com/Gaurav5091/
"""

import argparse
import sys
from modules.owasp import OWASPScanner
from modules.pentest.nmap_scan import NmapScanner
from modules.pentest.subdomains import SubdomainEnumerator
from modules.pentest.dir_brute import DirectoryBruteForcer
from modules.pentest.exploits import ExploitTester
from modules.pentest.linpeas import CustomLinPEAS
import config

def print_findings(findings):
    if findings:
        print("[!] Findings detected:")
        for finding in findings:
            print(f"- {finding}")

def save_report(target, findings):
    report_file = f"report_{target.replace('http://', '').replace('https://', '').replace('/', '_')}.txt"
    with open(report_file, 'w') as f:
        f.write("CyberTool Scan Report\n")
        f.write(f"Target: {target}\n")
        f.write("Author: Gaurav Kumar (https://github.com/Gaurav5091/)\n\n")
        f.write("Findings:\n")
        for finding in findings:
            f.write(f"- {finding}\n")
    print(f"[*] Report saved to {report_file}")

def main():
    parser = argparse.ArgumentParser(description="CyberTool - Penetration Testing Automation by Gaurav Kumar")
    parser.add_argument("target", help="Target URL or IP (e.g., http://example.com or 192.168.1.1)")
    parser.add_argument("--owasp", action="store_true", help="Run OWASP Top 10 vulnerability scan")
    parser.add_argument("--pentest", action="store_true", help="Run basic pentest automation")
    parser.add_argument("--advanced", action="store_true", help="Run advanced pentest features")
    parser.add_argument("--tor", action="store_true", help="Route scans through Tor")
    parser.add_argument("--anonymous", action="store_true", help="Use anonymous scanning techniques")
    
    args = parser.parse_args()
    target = args.target
    findings = []

    if args.owasp:
        owasp_scanner = OWASPScanner(target)
        findings.extend(owasp_scanner.scan())

    if args.pentest:
        nmap_scanner = NmapScanner(target)
        nmap_findings = nmap_scanner.scan()
        findings.extend(nmap_findings)

        subdomain_enum = SubdomainEnumerator(target)
        findings.extend(subdomain_enum.enumerate())

        dir_brute = DirectoryBruteForcer(target)
        findings.extend(dir_brute.brute_force())

        if args.advanced:
            exploit_tester = ExploitTester(target, nmap_findings)
            findings.extend(exploit_tester.test_exploits())

            linpeas = CustomLinPEAS()
            findings.extend(linpeas.run())

        if args.tor:
            findings.append("Tor routing enabled (ensure Tor service is running)")
        if args.anonymous:
            findings.append("Anonymous mode enabled")

    print_findings(findings)
    if findings:
        save_report(target, findings)

if __name__ == "__main__":
    main()
