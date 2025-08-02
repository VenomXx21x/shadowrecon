![release](https://img.shields.io/badge/release-v1.0.0-blue.svg)
![stars](https://img.shields.io/github/stars/CyberWarLab/shadowrecon?style=social)
![forks](https://img.shields.io/github/forks/CyberWarLab/shadowrecon?style=social)
![issues](https://img.shields.io/github/issues/CyberWarLab/shadowrecon)
![license](https://img.shields.io/badge/license-MIT-green.svg)

---

<img width="970" height="516" alt="image" src="https://github.com/user-attachments/assets/442e5a4f-e89e-40c3-8a44-1c792061203b" />
<img width="1351" height="762" alt="image" src="https://github.com/user-attachments/assets/c3377697-1362-4f14-857b-113578605a40" />


_**Like ShadowRecon? Consider supporting the developer:**_

[![Buy Me a Coffee](https://img.shields.io/badge/Buy%20Me%20a%20Coffee-%E2%98%95-yellow?style=flat-square)](https://www.buymeacoffee.com/yourusername)
[![Ko-Fi](https://img.shields.io/badge/Ko--fi-Donate-red?style=flat-square)](https://ko-fi.com/yourusername)

---

# 🕵️ ShadowRecon

**ShadowRecon** is a comprehensive, professional-grade web and network security assessment framework built for penetration testers, bug bounty hunters, and cybersecurity researchers.

Developed by **CyberWarLab**, ShadowRecon combines advanced reconnaissance, automated vulnerability discovery, OSINT, and reporting in one powerful Python CLI toolkit.

---

## 🧰 Installation (with Virtual Environment)

> ⚠️ It's strongly recommended to run ShadowRecon in an isolated Python virtual environment.

### ✅ Prerequisites

- Python 3.8+
- `git`, `pip3`

### 📥 Clone & Install

```bash
# Clone the repository
git clone https://github.com/CyberWarLab/shadowrecon.git
cd shadowrecon

# Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate  # for Linux/macOS
# venv\Scripts\activate    # for Windows (PowerShell)

# Install all dependencies
pip3 install --upgrade pip
pip3 install -r requirements.txt

# Run the tool
python3 shadowrecon.py


🚀 Features
🔎 Reconnaissance
DNS & WHOIS lookup

Subdomain enumeration

GeoIP location tracking

WAF detection

Security headers inspection

Admin panel finder

Phishing indicator scanning

🌐 Web Vulnerability Scanning
Detects XSS, SQLi, LFI, RCE, SSRF, CORS misconfig

GET, POST, and JSON payload support

Basic fuzzing for API endpoints

🧪 Network Security Assessment
Fast multithreaded port scanner

OS fingerprinting (via nmap)

Service detection

Vulnerability matching via built-in CVE database

🔍 OSINT Toolkit
Email harvesting via passive sources

Social media exposure lookup

Search engine scraping

🔐 SSL/TLS & WAF Analyzer
Identifies weak SSL ciphers

Detects common WAFs using headers, status codes, time-based fingerprinting

💣 Reverse Shell Generator
Payloads in Bash, Python, Perl, PHP, Ruby, Java, Netcat

Netcat listener + interactive PTY shell support

📊 (Coming Soon) Reporting System
Export scan results in HTML, JSON, or TXT

SQLite storage for session tracking

🧪 Usage Example
source venv/bin/activate
python3 shadowrecon.py

From the menu:

markdown
1. Advanced Reconnaissance Suite
2. Automated Vulnerability Scanner
3. Network Security Assessment
4. OSINT Intelligence Gathering
5. Phishing Detection Toolkit
6. Security Headers & SSL Analyzer
7. Admin Panel Finder
8. GeoIP Locator
9. Reverse Shell Generator
10. Advanced Web Testing
11. Exit


Web Testing sub-menu:

markdown
1. Test for XSS Vulnerabilities
2. Test for SQL Injection
3. Test for SSRF Vulnerabilities
4. Test for CORS Misconfigurations
5. Test API Endpoints

⚠️ Legal Disclaimer
ShadowRecon is provided strictly for authorized penetration testing and educational research.
Unauthorized scanning or exploitation of systems is illegal and unethical.

You are solely responsible for compliance with all applicable laws.
CyberWarLab assumes no liability for misuse or damage caused by this tool.

👤 Author
CyberWarLab
GitHub: @CyberWarLab
Ko-Fi: ko-fi.com/yourusername

“One framework. Complete reconnaissance, vulnerability scanning, and reporting. Automate and accelerate your security assessment workflow.”

⭐ Support the Project
If you find ShadowRecon useful:

⭐ Star the repository

🍕 Buy me a coffee

💬 Submit feedback or feature requests
