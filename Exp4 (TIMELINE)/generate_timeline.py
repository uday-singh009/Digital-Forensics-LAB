#!/usr/bin/env python3
"""
Experiment 4: Timeline Generation
Digital Forensics Lab
Generates a forensic timeline from filesystem metadata (MAC times)
"""

import os
import sys
import csv
import json
import hashlib
import stat
from datetime import datetime
from pathlib import Path

OUTPUT_DIR   = "timeline_output"
LOG_FILE     = "timeline_log.txt"
CSV_FILE     = os.path.join(OUTPUT_DIR, "timeline.csv")
JSON_FILE    = os.path.join(OUTPUT_DIR, "timeline.json")
REPORT_FILE  = os.path.join(OUTPUT_DIR, "timeline_report.txt")

# Target directory to analyze (change as needed)
TARGET_DIR   = "."


def log(msg):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {msg}"
    print(line)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")


def setup():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    log("=" * 60)
    log("EXPERIMENT 4 – Forensic Timeline Generation")
    log("=" * 60)


def get_file_type(path):
    if os.path.isdir(path):   return "DIR"
    if os.path.islink(path):  return "LINK"
    ext = Path(path).suffix.lower()
    type_map = {
        ".jpg": "IMAGE", ".jpeg": "IMAGE", ".png": "IMAGE",
        ".pdf": "PDF", ".doc": "DOCUMENT", ".docx": "DOCUMENT",
        ".txt": "TEXT", ".log": "LOG", ".py": "SCRIPT",
        ".sh": "SCRIPT", ".exe": "EXECUTABLE", ".dll": "LIBRARY",
        ".zip": "ARCHIVE", ".tar": "ARCHIVE",
    }
    return type_map.get(ext, "FILE")


def collect_mac_times(directory):
    log(f"\n[STEP 1] Collecting MAC times from: {os.path.abspath(directory)}")
    entries = []

    for root, dirs, files in os.walk(directory):
        all_items = dirs + files
        for item in all_items:
            full_path = os.path.join(root, item)
            try:
                s = os.stat(full_path)
                rel_path = os.path.relpath(full_path, directory)

                mtime = datetime.fromtimestamp(s.st_mtime)
                atime = datetime.fromtimestamp(s.st_atime)
                ctime = datetime.fromtimestamp(s.st_ctime)

                md5 = ""
                if os.path.isfile(full_path) and s.st_size < 10 * 1024 * 1024:
                    try:
                        with open(full_path, "rb") as f:
                            md5 = hashlib.md5(f.read()).hexdigest()
                    except Exception:
                        md5 = "N/A"

                entries.append({
                    "path":        rel_path,
                    "type":        get_file_type(full_path),
                    "size_bytes":  s.st_size,
                    "mtime":       mtime.strftime("%Y-%m-%d %H:%M:%S"),
                    "atime":       atime.strftime("%Y-%m-%d %H:%M:%S"),
                    "ctime":       ctime.strftime("%Y-%m-%d %H:%M:%S"),
                    "permissions": oct(stat.S_IMODE(s.st_mode)),
                    "md5":         md5,
                })
            except (PermissionError, OSError) as e:
                log(f"  [WARN] Cannot stat: {full_path} – {e}")

    log(f"  Collected {len(entries)} entries")
    return entries


def sort_and_save(entries):
    log("\n[STEP 2] Sorting timeline by modification time...")
    sorted_entries = sorted(entries, key=lambda x: x["mtime"])

    # Save CSV
    with open(CSV_FILE, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=sorted_entries[0].keys())
        writer.writeheader()
        writer.writerows(sorted_entries)
    log(f"  Saved CSV  -> {CSV_FILE}")

    # Save JSON
    with open(JSON_FILE, "w") as f:
        json.dump(sorted_entries, f, indent=2)
    log(f"  Saved JSON -> {JSON_FILE}")

    return sorted_entries


def detect_anomalies(entries):
    log("\n[STEP 3] Detecting potential anomalies...")
    anomalies = []

    for e in entries:
        # Flag files modified in the future
        mtime = datetime.strptime(e["mtime"], "%Y-%m-%d %H:%M:%S")
        if mtime > datetime.now():
            anomalies.append((e["path"], "FUTURE_MTIME", e["mtime"]))

        # Flag executable scripts
        if e["type"] == "SCRIPT" and e["size_bytes"] > 0:
            anomalies.append((e["path"], "SCRIPT_FILE", e["size_bytes"]))

        # Flag very large files
        if e["size_bytes"] > 100 * 1024 * 1024:
            anomalies.append((e["path"], "LARGE_FILE", f"{e['size_bytes']//1024//1024} MB"))

        # Flag world-writable (permissions ending in 7 or 6)
        if e["permissions"].endswith(("7", "6", "3", "2")):
            anomalies.append((e["path"], "WORLD_WRITABLE", e["permissions"]))

    log(f"  Found {len(anomalies)} anomalies")
    for path, reason, detail in anomalies[:20]:
        log(f"  [!] {reason:<20} {path}  ({detail})")

    return anomalies


def generate_report(entries, anomalies):
    log("\n[STEP 4] Generating report...")
    with open(REPORT_FILE, "w") as f:
        f.write("=" * 60 + "\n")
        f.write("FORENSIC TIMELINE REPORT\n")
        f.write(f"Generated : {datetime.now()}\n")
        f.write(f"Directory : {os.path.abspath(TARGET_DIR)}\n")
        f.write("=" * 60 + "\n\n")

        f.write(f"Total files analyzed : {len(entries)}\n")
        f.write(f"Anomalies detected   : {len(anomalies)}\n\n")

        f.write("--- EARLIEST EVENTS ---\n")
        for e in entries[:5]:
            f.write(f"  {e['mtime']}  {e['path']}\n")

        f.write("\n--- LATEST EVENTS ---\n")
        for e in entries[-5:]:
            f.write(f"  {e['mtime']}  {e['path']}\n")

        f.write("\n--- ANOMALIES ---\n")
        for path, reason, detail in anomalies:
            f.write(f"  [{reason}] {path} ({detail})\n")

    log(f"  Report saved -> {REPORT_FILE}")


if __name__ == "__main__":
    setup()
    target = sys.argv[1] if len(sys.argv) > 1 else TARGET_DIR
    entries = collect_mac_times(target)
    if not entries:
        log("[ERROR] No entries collected.")
        sys.exit(1)
    sorted_entries = sort_and_save(entries)
    anomalies = detect_anomalies(sorted_entries)
    generate_report(sorted_entries, anomalies)

    log("\n" + "=" * 60)
    log("TIMELINE GENERATION COMPLETE")
    log(f"Outputs in: {OUTPUT_DIR}/")
    log("=" * 60)
