#!/usr/bin/env python3
"""
Experiment 7: Browser Forensics
Digital Forensics Lab
Extracts browser history, cookies, downloads, and cached data from Chrome/Firefox
"""

import os
import sys
import json
import sqlite3
import shutil
import hashlib
from datetime import datetime, timezone
from pathlib import Path

OUTPUT_DIR  = "browser_output"
LOG_FILE    = "browser_log.txt"
REPORT_FILE = os.path.join(OUTPUT_DIR, "browser_report.json")

# Chrome timestamp epoch: Jan 1, 1601
CHROME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
# Firefox timestamp is in microseconds since Unix epoch
UNIX_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def log(msg):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {msg}"
    print(line)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")


def setup():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    log("=" * 60)
    log("EXPERIMENT 7 – Browser Forensics")
    log("=" * 60)


def chrome_time(microseconds):
    """Convert Chrome WebKit timestamp to human-readable datetime."""
    try:
        return (CHROME_EPOCH + __import__('datetime').timedelta(microseconds=microseconds)).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return "N/A"


def firefox_time(microseconds):
    """Convert Firefox timestamp (microseconds since epoch) to datetime."""
    try:
        return datetime.fromtimestamp(microseconds / 1_000_000, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return "N/A"


# ─────────────────────────────────────────
# DEMO: Create fake browser databases
# ─────────────────────────────────────────
def create_demo_databases():
    log("[DEMO] Creating sample browser databases...")
    demo_dir = os.path.join(OUTPUT_DIR, "demo_chrome")
    os.makedirs(demo_dir, exist_ok=True)

    # Chrome History DB
    history_path = os.path.join(demo_dir, "History")
    conn = sqlite3.connect(history_path)
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS urls (
        id INTEGER PRIMARY KEY, url TEXT, title TEXT,
        visit_count INTEGER, last_visit_time INTEGER)""")
    c.execute("""CREATE TABLE IF NOT EXISTS downloads (
        id INTEGER PRIMARY KEY, current_path TEXT, target_path TEXT,
        total_bytes INTEGER, state INTEGER, start_time INTEGER,
        tab_url TEXT, referrer TEXT)""")

    sample_urls = [
        (1, "https://www.google.com", "Google", 45, 13355555000000000),
        (2, "https://www.facebook.com/login", "Facebook Login", 12, 13355560000000000),
        (3, "http://malware-download.ru/payload.exe", "Free Software Download", 1, 13355570000000000),
        (4, "https://bankofamerica.com", "Bank of America", 8, 13355580000000000),
        (5, "https://pastebin.com/abc123", "Pastebin", 3, 13355590000000000),
        (6, "https://www.youtube.com", "YouTube", 100, 13355600000000000),
        (7, "http://192.168.1.1", "Router Admin", 5, 13355610000000000),
        (8, "https://github.com", "GitHub", 22, 13355620000000000),
    ]
    c.executemany("INSERT INTO urls VALUES (?,?,?,?,?)", sample_urls)

    sample_downloads = [
        (1, "/home/user/Downloads/payload.exe", "/tmp/payload.exe", 204800, 1, 13355570000000000, "http://malware-download.ru/payload.exe", "http://malware-download.ru"),
        (2, "/home/user/Downloads/resume.pdf", "/home/user/Downloads/resume.pdf", 512000, 1, 13355560000000000, "https://linkedin.com", ""),
    ]
    c.executemany("INSERT INTO downloads VALUES (?,?,?,?,?,?,?,?)", sample_downloads)
    conn.commit()
    conn.close()

    # Chrome Cookies DB
    cookies_path = os.path.join(demo_dir, "Cookies")
    conn = sqlite3.connect(cookies_path)
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS cookies (
        host_key TEXT, name TEXT, value TEXT, path TEXT,
        expires_utc INTEGER, is_secure INTEGER, is_httponly INTEGER,
        last_access_utc INTEGER)""")
    sample_cookies = [
        ("google.com",       "SSID",      "Abc123Token",     "/", 13400000000000000, 1, 1, 13355555000000000),
        ("facebook.com",     "c_user",    "100045678901234", "/", 13400000000000000, 1, 1, 13355560000000000),
        ("bankofamerica.com","session_id","sess_xyz_789",    "/", 13355590000000000, 1, 1, 13355580000000000),
    ]
    c.executemany("INSERT INTO cookies VALUES (?,?,?,?,?,?,?,?)", sample_cookies)
    conn.commit()
    conn.close()

    log(f"  Created demo databases in: {demo_dir}")
    return demo_dir


# ─────────────────────────────────────────
# EXTRACT CHROME HISTORY
# ─────────────────────────────────────────
def extract_chrome_history(db_path):
    log(f"\n[STEP 1] Extracting Chrome History from: {db_path}")
    history = []

    # Copy DB to avoid lock issues
    tmp = db_path + "_forensic_copy"
    shutil.copy2(db_path, tmp)

    try:
        conn = sqlite3.connect(tmp)
        c = conn.cursor()
        c.execute("SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC")
        rows = c.fetchall()
        conn.close()

        log(f"\n  {'Last Visit':<22} {'Visits':<8} {'Title':<30} URL")
        log(f"  {'-'*22} {'-'*8} {'-'*30} {'-'*40}")

        for url, title, count, ts in rows:
            human_ts = chrome_time(ts)
            log(f"  {human_ts:<22} {count:<8} {str(title)[:30]:<30} {url[:60]}")
            history.append({
                "url": url, "title": title,
                "visit_count": count,
                "last_visit": human_ts
            })

    except Exception as e:
        log(f"  [ERROR] {e}")
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)

    return history


# ─────────────────────────────────────────
# EXTRACT CHROME DOWNLOADS
# ─────────────────────────────────────────
def extract_chrome_downloads(db_path):
    log(f"\n[STEP 2] Extracting Chrome Downloads from: {db_path}")
    downloads = []
    tmp = db_path + "_forensic_copy"
    shutil.copy2(db_path, tmp)

    try:
        conn = sqlite3.connect(tmp)
        c = conn.cursor()
        c.execute("SELECT current_path, target_path, total_bytes, start_time, tab_url FROM downloads")
        rows = c.fetchall()
        conn.close()

        for path, target, size, ts, src_url in rows:
            human_ts = chrome_time(ts)
            log(f"  [{human_ts}] {os.path.basename(path)} ({size} bytes) from {src_url}")
            suspicious = any(ext in path.lower() for ext in [".exe", ".bat", ".ps1", ".scr", ".vbs"])
            entry = {
                "file": path, "size": size,
                "downloaded_at": human_ts,
                "source_url": src_url,
                "suspicious": suspicious
            }
            if suspicious:
                log(f"  [!!!] SUSPICIOUS DOWNLOAD: {path}")
            downloads.append(entry)

    except Exception as e:
        log(f"  [ERROR] {e}")
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)

    return downloads


# ─────────────────────────────────────────
# EXTRACT COOKIES
# ─────────────────────────────────────────
def extract_cookies(db_path):
    log(f"\n[STEP 3] Extracting Cookies from: {db_path}")
    cookies = []
    tmp = db_path + "_forensic_copy"
    shutil.copy2(db_path, tmp)

    try:
        conn = sqlite3.connect(tmp)
        c = conn.cursor()
        c.execute("SELECT host_key, name, value, path, is_secure, is_httponly, last_access_utc FROM cookies")
        rows = c.fetchall()
        conn.close()

        for host, name, value, path_, secure, httponly, ts in rows:
            human_ts = chrome_time(ts)
            # Redact session tokens in log (show only first 8 chars)
            safe_val = value[:8] + "..." if len(value) > 8 else value
            log(f"  {host:<30} {name:<20} {safe_val} (secure={bool(secure)})")
            cookies.append({
                "host": host, "name": name,
                "value_preview": safe_val,
                "secure": bool(secure),
                "httponly": bool(httponly),
                "last_access": human_ts
            })

    except Exception as e:
        log(f"  [ERROR] {e}")
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)

    return cookies


# ─────────────────────────────────────────
# FIND BROWSER PATHS
# ─────────────────────────────────────────
def find_browser_paths():
    log("\n[INFO] Common browser database locations:")
    paths = {
        "Chrome History (Linux)":   "~/.config/google-chrome/Default/History",
        "Chrome History (Windows)": r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\History",
        "Chrome History (Mac)":     "~/Library/Application Support/Google/Chrome/Default/History",
        "Firefox Places (Linux)":   "~/.mozilla/firefox/*.default/places.sqlite",
        "Firefox Places (Windows)": r"%APPDATA%\Mozilla\Firefox\Profiles\*.default\places.sqlite",
    }
    for name, path in paths.items():
        log(f"  {name}:\n    {path}")
    return paths


# ─────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────
if __name__ == "__main__":
    setup()

    demo_dir = create_demo_databases()
    history_db  = os.path.join(demo_dir, "History")
    cookies_db  = os.path.join(demo_dir, "Cookies")

    history   = extract_chrome_history(history_db)
    downloads = extract_chrome_downloads(history_db)
    cookies   = extract_cookies(cookies_db)

    find_browser_paths()

    report = {
        "analyzed_at": datetime.now().isoformat(),
        "browser": "Chrome (Demo)",
        "history_entries": len(history),
        "download_entries": len(downloads),
        "cookie_entries": len(cookies),
        "history": history,
        "downloads": downloads,
        "cookies": cookies,
    }

    with open(REPORT_FILE, "w") as f:
        json.dump(report, f, indent=2)

    log(f"\nReport saved -> {REPORT_FILE}")
    log("=" * 60)
    log("BROWSER FORENSICS COMPLETE")
    log("=" * 60)
