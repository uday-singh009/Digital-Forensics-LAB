#!/usr/bin/env python3
"""
Experiment 8: Android Forensics
Digital Forensics Lab
Extracts artifacts from Android devices using ADB (Android Debug Bridge)
"""

import os
import sys
import json
import subprocess
import shutil
from datetime import datetime

OUTPUT_DIR  = "android_output"
LOG_FILE    = "android_log.txt"
REPORT_FILE = os.path.join(OUTPUT_DIR, "android_report.json")

ANDROID_ARTIFACTS = {
    "SMS/MMS":       "/data/data/com.android.providers.telephony/databases/mmssms.db",
    "Call Logs":     "/data/data/com.android.providers.contacts/databases/contacts2.db",
    "Contacts":      "/data/data/com.android.providers.contacts/databases/contacts2.db",
    "WhatsApp":      "/data/data/com.whatsapp/databases/msgstore.db",
    "Browser Hist":  "/data/data/com.android.browser/databases/browser.db",
    "Chrome Hist":   "/data/data/com.android.chrome/app_chrome/Default/History",
    "Facebook":      "/data/data/com.facebook.katana/databases/",
    "GPS/Location":  "/data/data/com.google.android.location/files/",
    "Photos":        "/sdcard/DCIM/Camera/",
    "Downloads":     "/sdcard/Download/",
    "Installed Apps":"/data/app/",
    "Shared Prefs":  "/data/data/*/shared_prefs/",
}


def log(msg):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {msg}"
    print(line)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")


def setup():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    log("=" * 60)
    log("EXPERIMENT 8 – Android Forensics (ADB)")
    log("=" * 60)


def run_adb(args, capture=True):
    """Run an ADB command and return output."""
    cmd = ["adb"] + args
    try:
        result = subprocess.run(cmd, capture_output=capture, text=True, timeout=30)
        return result.stdout.strip(), result.returncode
    except FileNotFoundError:
        return "ADB_NOT_FOUND", -1
    except subprocess.TimeoutExpired:
        return "TIMEOUT", -1
    except Exception as e:
        return str(e), -1


# ─────────────────────────────────────────
# STEP 1: Device Detection
# ─────────────────────────────────────────
def check_device():
    log("\n[STEP 1] Checking ADB device connection...")
    out, rc = run_adb(["devices"])
    log(f"  $ adb devices")
    log(f"  {out}")

    if "ADB_NOT_FOUND" in out:
        log("  [WARN] ADB not installed. Install Android SDK Platform Tools.")
        log("  Download: https://developer.android.com/studio/releases/platform-tools")
        return False
    if "device" in out and "offline" not in out:
        log("  [OK] Device connected.")
        return True
    else:
        log("  [WARN] No device connected (or USB debugging not enabled).")
        log("  Enable: Settings > Developer Options > USB Debugging")
        return False


# ─────────────────────────────────────────
# STEP 2: Device Info
# ─────────────────────────────────────────
def get_device_info():
    log("\n[STEP 2] Collecting device information...")
    props = {
        "Model":          "ro.product.model",
        "Brand":          "ro.product.brand",
        "Android Ver":    "ro.build.version.release",
        "SDK Level":      "ro.build.version.sdk",
        "Serial":         "ro.serialno",
        "IMEI":           "ril.serialnumber",
        "Build ID":       "ro.build.id",
        "Manufacturer":   "ro.product.manufacturer",
    }
    info = {}
    for label, prop in props.items():
        out, rc = run_adb(["shell", "getprop", prop])
        if rc == 0 and out:
            log(f"  {label:<16}: {out}")
            info[label] = out
        else:
            info[label] = "N/A (device not connected)"
            log(f"  {label:<16}: N/A")
    return info


# ─────────────────────────────────────────
# STEP 3: Pull key databases
# ─────────────────────────────────────────
def pull_databases(device_connected):
    log("\n[STEP 3] Pulling forensic databases...")
    pulled = {}

    if not device_connected:
        log("  [DEMO] Simulating database pull (no device connected).")
        # Create demo SQLite databases
        import sqlite3

        # SMS database demo
        sms_dir = os.path.join(OUTPUT_DIR, "databases")
        os.makedirs(sms_dir, exist_ok=True)
        sms_path = os.path.join(sms_dir, "mmssms.db")
        conn = sqlite3.connect(sms_path)
        c = conn.cursor()
        c.execute("""CREATE TABLE IF NOT EXISTS sms (
            _id INTEGER PRIMARY KEY, address TEXT, date INTEGER,
            type INTEGER, body TEXT, read INTEGER)""")
        demo_sms = [
            (1, "+1-555-0101", 1705312980000, 1, "Hey, are you coming tonight?", 1),
            (2, "+1-555-0102", 1705313100000, 2, "Yes, be there at 8", 1),
            (3, "+1-555-0199", 1705320000000, 1, "The package has been delivered", 0),
            (4, "+91-9876543210", 1705321000000, 1, "Your OTP is 847291", 1),
        ]
        c.executemany("INSERT INTO sms VALUES (?,?,?,?,?,?)", demo_sms)
        conn.commit()
        conn.close()
        log(f"  [DEMO] Created: {sms_path}")
        pulled["SMS"] = sms_path

        # Call log demo
        call_path = os.path.join(sms_dir, "calls.db")
        conn = sqlite3.connect(call_path)
        c = conn.cursor()
        c.execute("""CREATE TABLE IF NOT EXISTS calls (
            _id INTEGER PRIMARY KEY, number TEXT, date INTEGER,
            duration INTEGER, type INTEGER)""")
        demo_calls = [
            (1, "+1-555-0101", 1705312800000, 120, 1),   # incoming
            (2, "+1-555-0199", 1705310000000, 0,   3),   # missed
            (3, "+91-9876543210", 1705305000000, 45, 2), # outgoing
        ]
        c.executemany("INSERT INTO calls VALUES (?,?,?,?,?)", demo_calls)
        conn.commit()
        conn.close()
        log(f"  [DEMO] Created: {call_path}")
        pulled["Calls"] = call_path

        return pulled

    # Real ADB pulls
    for name, remote_path in ANDROID_ARTIFACTS.items():
        local_path = os.path.join(OUTPUT_DIR, "pulled", name.replace("/", "_"))
        os.makedirs(os.path.dirname(local_path), exist_ok=True)
        log(f"  Pulling {name}...")
        out, rc = run_adb(["pull", remote_path, local_path])
        if rc == 0:
            log(f"    [OK] Saved to {local_path}")
            pulled[name] = local_path
        else:
            log(f"    [WARN] Could not pull {remote_path}: {out[:80]}")

    return pulled


# ─────────────────────────────────────────
# STEP 4: Parse SMS
# ─────────────────────────────────────────
def parse_sms(db_path):
    log(f"\n[STEP 4] Parsing SMS database: {db_path}")
    import sqlite3

    messages = []
    try:
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        c.execute("SELECT address, date, type, body FROM sms ORDER BY date DESC")
        rows = c.fetchall()
        conn.close()

        type_map = {1: "RECEIVED", 2: "SENT", 3: "DRAFT"}
        log(f"\n  {'Timestamp':<22} {'Type':<10} {'From/To':<20} Message")
        log(f"  {'-'*22} {'-'*10} {'-'*20} {'-'*30}")

        for addr, date_ms, type_, body in rows:
            ts = datetime.fromtimestamp(date_ms / 1000).strftime("%Y-%m-%d %H:%M:%S")
            sms_type = type_map.get(type_, f"TYPE_{type_}")
            log(f"  {ts:<22} {sms_type:<10} {str(addr)[:20]:<20} {str(body)[:50]}")
            messages.append({
                "address": addr, "timestamp": ts,
                "type": sms_type, "body": body
            })

    except Exception as e:
        log(f"  [ERROR] {e}")

    return messages


# ─────────────────────────────────────────
# STEP 5: Parse Call Logs
# ─────────────────────────────────────────
def parse_calls(db_path):
    log(f"\n[STEP 5] Parsing Call Log database: {db_path}")
    import sqlite3

    calls = []
    try:
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        c.execute("SELECT number, date, duration, type FROM calls ORDER BY date DESC")
        rows = c.fetchall()
        conn.close()

        type_map = {1: "INCOMING", 2: "OUTGOING", 3: "MISSED", 4: "VOICEMAIL"}
        log(f"\n  {'Timestamp':<22} {'Type':<12} {'Number':<20} {'Duration'}")
        log(f"  {'-'*22} {'-'*12} {'-'*20} {'-'*10}")

        for number, date_ms, duration, type_ in rows:
            ts = datetime.fromtimestamp(date_ms / 1000).strftime("%Y-%m-%d %H:%M:%S")
            call_type = type_map.get(type_, f"TYPE_{type_}")
            log(f"  {ts:<22} {call_type:<12} {str(number)[:20]:<20} {duration}s")
            calls.append({
                "number": number, "timestamp": ts,
                "duration_sec": duration, "type": call_type
            })

    except Exception as e:
        log(f"  [ERROR] {e}")

    return calls


# ─────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────
if __name__ == "__main__":
    setup()

    log("\n[INFO] Android Forensic Artifact Locations:")
    for name, path in ANDROID_ARTIFACTS.items():
        log(f"  {name:<16}: {path}")

    connected = check_device()
    device_info = get_device_info()
    pulled_dbs = pull_databases(connected)

    messages = []
    calls = []

    if "SMS" in pulled_dbs:
        messages = parse_sms(pulled_dbs["SMS"])
    if "Calls" in pulled_dbs:
        calls = parse_calls(pulled_dbs["Calls"])

    report = {
        "analyzed_at":  datetime.now().isoformat(),
        "device_info":  device_info,
        "adb_connected": connected,
        "sms_count":    len(messages),
        "call_count":   len(calls),
        "sms":          messages,
        "calls":        calls,
    }

    with open(REPORT_FILE, "w") as f:
        json.dump(report, f, indent=2)

    log(f"\nReport saved -> {REPORT_FILE}")
    log("=" * 60)
    log("ANDROID FORENSICS COMPLETE")
    log("=" * 60)
