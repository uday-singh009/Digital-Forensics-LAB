#!/usr/bin/env python3
"""
Experiment 6: Email Forensics
Digital Forensics Lab
Analyzes email headers, detects spoofing, extracts attachments, traces routing
"""

import os
import re
import json
import email
import hashlib
import base64
import ipaddress
from email import policy
from email.parser import BytesParser, Parser
from datetime import datetime

OUTPUT_DIR  = "email_output"
LOG_FILE    = "email_log.txt"
REPORT_FILE = os.path.join(OUTPUT_DIR, "email_report.json")

SAMPLE_EMAIL = """From: "John Doe" <john.doe@example.com>
To: victim@target.com
Subject: Urgent: Your account needs verification
Date: Mon, 15 Jan 2024 14:23:00 +0000
Message-ID: <abc123@mail.example.com>
Received: from mail.attacker.ru (mail.attacker.ru [185.220.101.45])
    by mx.target.com with ESMTP id xyz789
    for <victim@target.com>; Mon, 15 Jan 2024 14:23:00 +0000
Received: from localhost (localhost [127.0.0.1])
    by mail.attacker.ru with ESMTP id local001
    Mon, 15 Jan 2024 14:22:55 +0000
X-Originating-IP: 185.220.101.45
X-Mailer: PHPMailer 6.1.8
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="boundary_forensics_demo"
Return-Path: bounce@attacker.ru
Reply-To: reply@different-domain.net

--boundary_forensics_demo
Content-Type: text/plain; charset=UTF-8

Dear Customer,

Please click the link below to verify your account:
http://phish.attacker.ru/verify?token=abc123

Your account will be suspended in 24 hours.

Best regards,
Security Team

--boundary_forensics_demo
Content-Type: application/octet-stream; name="invoice.exe"
Content-Disposition: attachment; filename="invoice.exe"
Content-Transfer-Encoding: base64

TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAA4AAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9T

--boundary_forensics_demo--
"""


def log(msg):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {msg}"
    print(line)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")


def setup():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    log("=" * 60)
    log("EXPERIMENT 6 – Email Forensics")
    log("=" * 60)


# ─────────────────────────────────────────
# PARSE EMAIL
# ─────────────────────────────────────────
def parse_email(raw_email):
    log("\n[STEP 1] Parsing email structure...")
    msg = Parser(policy=policy.default).parsestr(raw_email)

    headers = {}
    for key in msg.keys():
        headers[key] = msg[key]

    log(f"  From    : {msg.get('From', 'N/A')}")
    log(f"  To      : {msg.get('To', 'N/A')}")
    log(f"  Subject : {msg.get('Subject', 'N/A')}")
    log(f"  Date    : {msg.get('Date', 'N/A')}")
    log(f"  Msg-ID  : {msg.get('Message-ID', 'N/A')}")

    return msg, headers


# ─────────────────────────────────────────
# TRACE ROUTING PATH
# ─────────────────────────────────────────
def trace_routing(msg):
    log("\n[STEP 2] Tracing email routing path...")
    received_headers = msg.get_all("Received") or []
    hops = []

    ip_pattern = re.compile(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]')

    for i, hop in enumerate(reversed(received_headers)):
        ips = ip_pattern.findall(hop)
        hop_info = {
            "hop": i + 1,
            "raw": hop.strip(),
            "ips_found": ips,
            "is_private": []
        }
        for ip in ips:
            try:
                hop_info["is_private"].append(
                    ipaddress.ip_address(ip).is_private
                )
            except ValueError:
                hop_info["is_private"].append(None)

        log(f"  Hop {i+1}: IPs={ips}")
        hops.append(hop_info)

    return hops


# ─────────────────────────────────────────
# DETECT SPOOFING / ANOMALIES
# ─────────────────────────────────────────
def detect_spoofing(msg, headers):
    log("\n[STEP 3] Checking for spoofing and anomalies...")
    findings = []

    from_addr    = msg.get("From", "")
    reply_to     = msg.get("Reply-To", "")
    return_path  = msg.get("Return-Path", "")
    x_orig_ip    = msg.get("X-Originating-IP", "")

    def extract_domain(addr):
        m = re.search(r'@([\w\.-]+)', addr)
        return m.group(1).lower() if m else ""

    from_domain       = extract_domain(from_addr)
    reply_to_domain   = extract_domain(reply_to)
    return_path_domain= extract_domain(return_path)

    # Check Reply-To mismatch
    if reply_to and reply_to_domain != from_domain:
        msg_ = f"[!] REPLY-TO MISMATCH: From={from_domain}, Reply-To={reply_to_domain}"
        log(f"  {msg_}")
        findings.append(msg_)

    # Check Return-Path mismatch
    if return_path and return_path_domain != from_domain:
        msg_ = f"[!] RETURN-PATH MISMATCH: From={from_domain}, Return-Path={return_path_domain}"
        log(f"  {msg_}")
        findings.append(msg_)

    # Check for suspicious X-Originating-IP
    if x_orig_ip:
        try:
            ip = ipaddress.ip_address(x_orig_ip)
            msg_ = f"[INFO] X-Originating-IP: {x_orig_ip} (Private: {ip.is_private})"
            log(f"  {msg_}")
            findings.append(msg_)
        except ValueError:
            pass

    # Check for suspicious keywords in subject
    subject = msg.get("Subject", "").lower()
    suspicious_words = ["urgent", "verify", "suspended", "account", "click", "password"]
    for word in suspicious_words:
        if word in subject:
            findings.append(f"[!] SUSPICIOUS SUBJECT KEYWORD: '{word}'")
            log(f"  [!] Suspicious keyword in subject: '{word}'")

    # Check X-Mailer
    mailer = msg.get("X-Mailer", "")
    if "phpmailer" in mailer.lower():
        findings.append(f"[!] PHPMAILER DETECTED: {mailer} (common in spam/phishing)")
        log(f"  [!] PHPMailer detected: {mailer}")

    return findings


# ─────────────────────────────────────────
# EXTRACT ATTACHMENTS
# ─────────────────────────────────────────
def extract_attachments(msg):
    log("\n[STEP 4] Extracting attachments...")
    attachments = []

    for part in msg.walk():
        content_disp = part.get("Content-Disposition", "")
        if "attachment" in content_disp:
            filename = part.get_filename() or "unknown_attachment"
            payload  = part.get_payload(decode=True) or b""

            out_path = os.path.join(OUTPUT_DIR, f"attachment_{filename}")
            with open(out_path, "wb") as f:
                f.write(payload)

            md5 = hashlib.md5(payload).hexdigest()
            sha256 = hashlib.sha256(payload).hexdigest()

            info = {
                "filename": filename,
                "size":     len(payload),
                "md5":      md5,
                "sha256":   sha256,
                "saved_to": out_path,
            }

            # Detect EXE/script
            if filename.lower().endswith((".exe", ".bat", ".ps1", ".js", ".vbs", ".scr")):
                info["warning"] = "POTENTIALLY MALICIOUS EXECUTABLE"
                log(f"  [!!!] EXECUTABLE ATTACHMENT: {filename} (MD5: {md5})")
            else:
                log(f"  [ATTACH] {filename} ({len(payload)} bytes) MD5:{md5}")

            attachments.append(info)

    if not attachments:
        log("  No attachments found.")

    return attachments


# ─────────────────────────────────────────
# EXTRACT URLS
# ─────────────────────────────────────────
def extract_urls(msg):
    log("\n[STEP 5] Extracting URLs from email body...")
    urls = []
    url_pattern = re.compile(r'https?://[^\s<>"]+')

    for part in msg.walk():
        ctype = part.get_content_type()
        if ctype in ("text/plain", "text/html"):
            body = part.get_payload(decode=True)
            if body:
                body_str = body.decode("utf-8", errors="ignore")
                found = url_pattern.findall(body_str)
                for url in found:
                    log(f"  [URL] {url}")
                    suspicious = any(kw in url.lower() for kw in ["phish", "verify", "login", "secure", "account"])
                    urls.append({"url": url, "suspicious": suspicious})

    return urls


# ─────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────
if __name__ == "__main__":
    import sys
    setup()

    if len(sys.argv) > 1 and os.path.exists(sys.argv[1]):
        with open(sys.argv[1], "r", errors="ignore") as f:
            raw = f.read()
        log(f"[INFO] Analyzing file: {sys.argv[1]}")
    else:
        raw = SAMPLE_EMAIL
        log("[INFO] Using built-in sample phishing email for demonstration.")

    msg, headers = parse_email(raw)
    hops         = trace_routing(msg)
    findings     = detect_spoofing(msg, headers)
    attachments  = extract_attachments(msg)
    urls         = extract_urls(msg)

    report = {
        "analyzed_at": datetime.now().isoformat(),
        "from":        msg.get("From"),
        "to":          msg.get("To"),
        "subject":     msg.get("Subject"),
        "date":        msg.get("Date"),
        "routing_hops": hops,
        "spoofing_findings": findings,
        "attachments": attachments,
        "urls":        urls,
    }

    with open(REPORT_FILE, "w") as f:
        json.dump(report, f, indent=2)

    log(f"\nReport saved -> {REPORT_FILE}")
    log("=" * 60)
    log("EMAIL FORENSICS COMPLETE")
    log("=" * 60)
