from datetime import datetime

def generate_report(vulnerabilities, output_file="report.txt"):
    with open(output_file, "w") as f:
        f.write(f"=== Cybersecurity Tool Report ({datetime.now()}) ===\n")
        f.write(f"Target: {output_file.split('.')[0].replace('report_', '')}\n\n")
        if vulnerabilities:
            f.write("Vulnerabilities Found:\n")
            for vuln in sorted(vulnerabilities):
                f.write(f"- {vuln}\n")
        else:
            f.write("No vulnerabilities detected.\n")
    print(f"[*] Report saved to {output_file}")
