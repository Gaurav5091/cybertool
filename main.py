import argparse
import os
from modules.owasp import OWASPScanner
from modules.pentest.pentest import PentestAutomation
from utils.report import generate_report

def main():
    parser = argparse.ArgumentParser(description="Cybersecurity Automation Tool")
    parser.add_argument("url", help="Target website URL (e.g., http://example.com)")
    parser.add_argument("--owasp", action="store_true", help="Run OWASP Top 10 scan")
    parser.add_argument("--pentest", action="store_true", help="Run penetration testing automation")
    parser.add_argument("--advanced", action="store_true", help="Run advanced thorough scan (includes LinPEAS on Linux)")
    parser.add_argument("--anonymous", action="store_true", help="Run Nmap anonymously to evade firewalls")
    parser.add_argument("--tor", action="store_true", help="Route Nmap scan through Tor")
    args = parser.parse_args()

    all_findings = []
    if args.owasp:
        owasp_scanner = OWASPScanner(args.url, advanced=args.advanced)
        all_findings.extend(owasp_scanner.scan())
    
    if args.pentest:
        pentest_automation = PentestAutomation(args.url, advanced=args.advanced, 
                                              anonymous=args.anonymous, use_tor=args.tor)
        all_findings.extend(pentest_automation.run())

    if all_findings:
        print("\n[!] Findings detected:")
        for finding in all_findings:
            print(f"- {finding}")
    else:
        print("\n[+] No findings in scan.")
    
    report_file = f"report_{args.url.replace('http://', '').replace('https://', '').replace('/', '_')}.txt"
    generate_report(all_findings, report_file)

if __name__ == "__main__":
    main()
