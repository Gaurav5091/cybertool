cat << 'EOF' > README.md
# CyberTool - Cybersecurity Automation Tool

A Python-based tool for automating cybersecurity tasks, including OWASP Top 10 vulnerability scanning and penetration testing automation.

## Features
- **OWASP Top 10 Scanning**: Detects vulnerabilities like SQL injection, XSS, and more.
- **Pentest Automation**:
  - Nmap scanning with anonymity (decoys, Tor).
  - Subdomain enumeration (DNS, HTTP, Amass).
  - Directory brute-forcing.
  - Exploit testing with Metasploit integration.
  - Custom LinPEAS (Linux privilege escalation checks, runs locally).

## Prerequisites
- **Python 3.8+**
- **External Tools**:
  - Nmap (`sudo apt install nmap`)
  - Tor (`sudo apt install tor`) and Proxychains (`sudo apt install proxychains`)
  - Metasploit (`sudo apt install metasploit-framework`)
  - Amass (`go install github.com/OWASP/Amass/v3/...@master`)
- **Wordlists**: Included in `wordlists/` (or replace with SecLists)

## Installation
1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd cybertool
