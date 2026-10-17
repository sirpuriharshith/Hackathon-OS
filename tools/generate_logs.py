#!/usr/bin/env python3
"""
MultiLog-OS: High-Performance Multithreaded Log Analysis & Threat Detection System
File: tools/generate_logs.py

Generates realistic synthetic log datasets with controlled proportions of:
- Benign Traffic (HTTP 200, 301, 304)
- Errors (HTTP 500, 502, 503, OOM, Segmentation Faults, Database Connection Drops)
- Warnings (HTTP 400, 401, 403, 404, Deprecations, High Latency Thresholds)
- Suspicious Threat Events (SQLi, XSS, Directory Traversal, Recon Probes, Brute Force SSH, Privilege Escalation)
"""

import sys
import os
import random
import argparse
from datetime import datetime, timedelta

IPS = [
    "192.168.1.15", "10.0.0.42", "172.16.0.8", "192.168.1.100",
    "203.0.113.19", "198.51.100.4", "45.33.32.156", "185.220.101.5",
    "194.26.29.112", "103.251.167.20", "89.248.163.74", "91.240.118.172"
]

ATTACKER_IPS = [
    "185.220.101.5", "194.26.29.112", "103.251.167.20", "89.248.163.74"
]

BENIGN_PATHS = [
    "/index.html", "/about", "/contact", "/api/v1/products", "/api/v1/user/profile",
    "/static/css/main.css", "/static/js/bundle.js", "/images/logo.png",
    "/favicon.ico", "/checkout", "/catalog/category/electronics", "/search?q=laptop"
]

SQLI_PAYLOADS = [
    "/products?cat=1%20UNION%20SELECT%20username,password%20FROM%20users--",
    "/search?query=admin'%20OR%20'1'='1'--",
    "/login?user=admin'%20OR%201=1--&pass=x",
    "/api/items?id=10%20WAITFOR%20DELAY%20'0:0:5'",
    "/catalog?sort=id%20UNION%20ALL%20SELECT%20NULL,table_name%20FROM%20information_schema.tables--",
    "/user?id=1;%20DROP%20TABLE%20audit_log;--"
]

XSS_PAYLOADS = [
    "/search?q=<script>alert('XSS')</script>",
    "/comment?text=<iframe%20src=javascript:alert(document.cookie)>",
    "/profile?name=<img%20src=x%20onerror=alert(1)>",
    "/feedback?msg=<svg/onload=alert('pwned')>"
]

DIR_TRAVERSAL_PAYLOADS = [
    "/download?file=../../../../etc/passwd",
    "/view?page=..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
    "/static?doc=../../../../etc/shadow",
    "/read?path=..\\..\\boot.ini",
    "/file?name=../../../../windows/win.ini"
]

RECON_PROBES = [
    "/wp-login.php", "/wp-admin/install.php", "/.env", "/.git/config",
    "/phpmyadmin/index.php", "/actuator/health", "/cgi-bin/test-cgi",
    "/web-console/ServerInfo.jsp", "/solr/admin/info/system", "/api/v1/debug"
]

ERROR_MESSAGES = [
    "Database connection pool exhausted: timeout waiting for idle connection",
    "Kernel panic - not syncing: Fatal exception in interrupt",
    "Out of memory: Kill process 18422 (mysqld) score 852 or sacrifice child",
    "Segmentation fault: core dumped at address 0x7fff5a892b00",
    "Fatal error: Uncaught RedisException: Connection refused to redis:6379",
    "HTTP 500 Internal Server Error in /var/www/backend/payment_gateway.c:142",
    "Exception in thread 'worker-pool-3' java.lang.OutOfMemoryError: Java heap space"
]

WARN_MESSAGES = [
    "Warning: Slow query detected - execution took 3421ms on SELECT * FROM transactions",
    "Deprecation notice: API endpoint /v1/auth is deprecated and will be removed in next release",
    "Warning: Disk usage on volume /dev/sda1 reached 88% threshold",
    "Threshold exceeded: Worker thread 4 CPU utilization peaked at 94.2%",
    "Retry attempt 3 of 5 failed for downstream microservice payment-worker",
    "Connection reset by peer during TLS handshake renegotiation"
]

AUTH_FAILURES = [
    "sshd[24819]: Failed password for invalid user admin from {ip} port {port} ssh2",
    "sshd[24820]: Failed password for root from {ip} port {port} ssh2",
    "sshd[24821]: PAM 2 more authentication failures; logname= uid=0 euid=0 tty=ssh ruser= rhost={ip}",
    "auth-service: Invalid credentials supplied for username 'administrator' from {ip}"
]

PRIVILEGE_ESCALATIONS = [
    "sudo: auth failure: user=guest ; TTY=pts/2 ; PWD=/tmp ; USER=root ; COMMAND=/bin/sh",
    "sudo: guest : 3 incorrect password attempts ; TTY=pts/1 ; COMMAND=/bin/bash",
    "kernel: Security alert: unauthorized su attempt by uid=1004 (tester) to gid=0 (root)"
]

def generate_log_line(timestamp: datetime, index: int) -> str:
    roll = random.random()
    dt_str = timestamp.strftime("%d/%b/%Y:%H:%M:%S +0530")
    iso_str = timestamp.strftime("%Y-%m-%d %H:%M:%S")

    # 1. Security Threat: SQL Injection (~3%)
    if roll < 0.03:
        ip = random.choice(ATTACKER_IPS)
        payload = random.choice(SQLI_PAYLOADS)
        return f'{ip} - - [{dt_str}] "GET {payload} HTTP/1.1" 500 892 "-" "Mozilla/5.0 (Hydra-Attack-Tool)"\n'

    # 2. Security Threat: XSS (~2%)
    elif roll < 0.05:
        ip = random.choice(ATTACKER_IPS)
        payload = random.choice(XSS_PAYLOADS)
        return f'{ip} - - [{dt_str}] "GET {payload} HTTP/1.1" 400 621 "-" "Mozilla/5.0"\n'

    # 3. Security Threat: Directory Traversal (~2%)
    elif roll < 0.07:
        ip = random.choice(ATTACKER_IPS)
        payload = random.choice(DIR_TRAVERSAL_PAYLOADS)
        return f'{ip} - - [{dt_str}] "GET {payload} HTTP/1.1" 403 412 "-" "curl/7.81.0"\n'

    # 4. Security Threat: Reconnaissance Probes (~3%)
    elif roll < 0.10:
        ip = random.choice(ATTACKER_IPS)
        probe = random.choice(RECON_PROBES)
        return f'{ip} - - [{dt_str}] "GET {probe} HTTP/1.1" 404 318 "-" "Nikto/2.1.6"\n'

    # 5. Security Threat: SSH Brute Force / Auth Failure (~3%)
    elif roll < 0.13:
        ip = random.choice(ATTACKER_IPS)
        port = random.randint(30000, 65535)
        pattern = random.choice(AUTH_FAILURES)
        msg = pattern.format(ip=ip, port=port)
        return f'{timestamp.strftime("%b %d %H:%M:%S")} srv-node01 {msg}\n'

    # 6. Security Threat: Privilege Escalation (~1%)
    elif roll < 0.14:
        msg = random.choice(PRIVILEGE_ESCALATIONS)
        return f'{timestamp.strftime("%b %d %H:%M:%S")} srv-node01 {msg}\n'

    # 7. System & Application Errors (~6%)
    elif roll < 0.20:
        ip = random.choice(IPS)
        path = random.choice(BENIGN_PATHS)
        err = random.choice(ERROR_MESSAGES)
        if random.random() < 0.5:
            return f'{ip} - - [{dt_str}] "POST {path} HTTP/1.1" 500 2480 [error] {err}\n'
        else:
            return f'[{iso_str}] [ERROR] [worker-thread-{random.randint(1,8)}] {err} (client={ip})\n'

    # 8. Warnings (~10%)
    elif roll < 0.30:
        ip = random.choice(IPS)
        path = random.choice(BENIGN_PATHS)
        warn = random.choice(WARN_MESSAGES)
        status = random.choice([401, 403, 404, 429])
        if random.random() < 0.5:
            return f'{ip} - - [{dt_str}] "GET {path} HTTP/1.1" {status} 1250 [warn] {warn}\n'
        else:
            return f'[{iso_str}] [WARN] [gateway-proxy] {warn} - request_id={random.randint(100000,999999)}\n'

    # 9. Normal Benign HTTP Traffic (~70%)
    else:
        ip = random.choice(IPS)
        path = random.choice(BENIGN_PATHS)
        status = random.choice([200, 200, 200, 200, 201, 301, 304])
        size = random.randint(256, 32768)
        return f'{ip} - - [{dt_str}] "GET {path} HTTP/1.1" {status} {size} "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"\n'

def main():
    parser = argparse.ArgumentParser(description="MultiLog-OS Synthetic Log Generator")
    parser.add_argument("--lines", type=int, default=50000, help="Number of log records to generate")
    parser.add_argument("--out", type=str, default="data/sample.log", help="Output log file path")
    parser.add_argument("--preset", type=str, choices=["small", "medium", "large", "stress"], help="Preset size")
    args = parser.parse_args()

    preset_map = {
        "small": 10000,      # ~1.5 MB
        "medium": 100000,    # ~15 MB
        "large": 500000,     # ~75 MB
        "stress": 1000000    # ~150 MB
    }

    total_lines = preset_map.get(args.preset, args.lines)
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)

    print(f"[*] Generating {total_lines:,} synthetic log records into '{args.out}'...")
    base_time = datetime(2026, 10, 16, 12, 0, 0)
    
    with open(args.out, "w", encoding="utf-8", buffering=1024*1024) as f:
        for i in range(total_lines):
            t = base_time + timedelta(seconds=i // 20)
            f.write(generate_log_line(t, i))

    file_size_mb = os.path.getsize(args.out) / (1024 * 1024)
    print(f"[SUCCESS] Generated {total_lines:,} lines ({file_size_mb:.2f} MB) in '{args.out}'.")

if __name__ == "__main__":
    main()
