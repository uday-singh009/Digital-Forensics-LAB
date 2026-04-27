#!/usr/bin/env python3
"""
Experiment 3: RAM Capture and Memory Analysis
Digital Forensics Lab
Uses: Volatility 3 framework simulation + live memory capture steps
"""

import os
import sys
import subprocess
import hashlib
import json
import struct
from datetime import datetime

LOG_FILE   = "memory_analysis_log.txt"
OUTPUT_DIR = "memory_output"
DEMO_DUMP  = "demo_memory.raw"


def log(msg):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {msg}"
    print(line)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")


def setup():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    log("=" * 60)
    log("EXPERIMENT 3 – RAM Capture & Memory Analysis")
    log("=" * 60)


# ─────────────────────────────────────────
# DEMO: Create a simulated memory dump
# ─────────────────────────────────────────
def create_demo_dump():
    log("[DEMO] Generating simulated memory dump...")
    import random, string

    fake_processes = [
        b"System\x00\x00\x00\x00",
        b"smss.exe\x00\x00\x00",
        b"csrss.exe\x00\x00\x00",
        b"winlogon.exe\x00",
        b"services.exe\x00",
        b"lsass.exe\x00\x00\x00",
        b"explorer.exe\x00",
        b"chrome.exe\x00\x00\x00",
        b"cmd.exe\x00\x00\x00\x00",
        b"notepad.exe\x00\x00",
    ]
    fake_networks = [
        b"192.168.1.100:49201 -> 142.250.80.46:443 ESTABLISHED",
        b"10.0.0.5:52314 -> 52.86.112.4:80 CLOSE_WAIT",
        b"127.0.0.1:3306 -> 127.0.0.1:49310 LISTENING",
    ]
    fake_strings = [
        b"password=Sup3rS3cr3t!",
        b"http://malware-c2.example.com/beacon",
        b"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        b"CreateRemoteThread",
        b"VirtualAllocEx",
    ]

    with open(DEMO_DUMP, "wb") as f:
        f.write(b"\x00" * 4096)
        for proc in fake_processes:
            f.write(b"\x00" * random.randint(64, 256))
            f.write(proc)
        for net in fake_networks:
            f.write(b"\x00" * random.randint(128, 512))
            f.write(net)
        for s in fake_strings:
            f.write(b"\x00" * random.randint(64, 256))
            f.write(s)
        f.write(b"\x00" * 8192)

    size = os.path.getsize(DEMO_DUMP)
    log(f"[DEMO] Created {DEMO_DUMP} ({size} bytes)")
    return DEMO_DUMP


# ─────────────────────────────────────────
# STEP 1: Hash the memory dump
# ─────────────────────────────────────────
def hash_dump(dump_path):
    log(f"\n[STEP 1] Hashing memory dump: {dump_path}")
    with open(dump_path, "rb") as f:
        data = f.read()
    md5  = hashlib.md5(data).hexdigest()
    sha1 = hashlib.sha1(data).hexdigest()
    log(f"  MD5    : {md5}")
    log(f"  SHA1   : {sha1}")
    with open(os.path.join(OUTPUT_DIR, "dump_hashes.txt"), "w") as f:
        f.write(f"File : {dump_path}\nMD5  : {md5}\nSHA1 : {sha1}\n")
    return md5


# ─────────────────────────────────────────
# STEP 2: Extract strings
# ─────────────────────────────────────────
def extract_strings(dump_path, min_len=6):
    log(f"\n[STEP 2] Extracting printable strings (min length={min_len})...")
    with open(dump_path, "rb") as f:
        data = f.read()

    result = []
    current = []
    for byte in data:
        if 32 <= byte <= 126:
            current.append(chr(byte))
        else:
            if len(current) >= min_len:
                result.append("".join(current))
            current = []

    out_path = os.path.join(OUTPUT_DIR, "strings.txt")
    with open(out_path, "w") as f:
        for s in result:
            f.write(s + "\n")

    log(f"  Extracted {len(result)} strings -> {out_path}")

    # Show interesting strings
    keywords = ["password", "http", "HKEY", "cmd", "exec", "malware", "c2", "TOKEN"]
    log("\n  [!] Interesting strings found:")
    for s in result:
        for kw in keywords:
            if kw.lower() in s.lower():
                log(f"      >> {s}")
                break


# ─────────────────────────────────────────
# STEP 3: Simulate Volatility process listing
# ─────────────────────────────────────────
def simulate_pslist(dump_path):
    log(f"\n[STEP 3] Simulating vol3 windows.pslist...")
    with open(dump_path, "rb") as f:
        data = f.read()

    process_names = []
    i = 0
    while i < len(data) - 4:
        chunk = data[i:i+16].replace(b"\x00", b"")
        decoded = chunk.decode("ascii", errors="ignore").strip()
        if decoded.endswith(".exe") or decoded in ["System", "smss"]:
            process_names.append((i, decoded))
        i += 8

    log(f"\n  {'Offset':<14} {'Name':<24} {'PID (simulated)'}")
    log(f"  {'-'*14} {'-'*24} {'-'*20}")
    seen = set()
    pid = 4
    out_rows = []
    for offset, name in process_names:
        if name not in seen:
            log(f"  {offset:#010x}   {name:<24} {pid}")
            out_rows.append({"offset": hex(offset), "name": name, "pid": pid})
            seen.add(name)
            pid += 4

    out_path = os.path.join(OUTPUT_DIR, "pslist.json")
    with open(out_path, "w") as f:
        json.dump(out_rows, f, indent=2)
    log(f"\n  Saved process list -> {out_path}")


# ─────────────────────────────────────────
# STEP 4: Simulate network connections
# ─────────────────────────────────────────
def simulate_netstat(dump_path):
    log(f"\n[STEP 4] Simulating vol3 windows.netstat...")
    with open(dump_path, "rb") as f:
        data = f.read()

    connections = []
    search = b"192."
    idx = 0
    while True:
        pos = data.find(search, idx)
        if pos == -1:
            break
        chunk = data[pos:pos+80].split(b"\x00")[0]
        decoded = chunk.decode("ascii", errors="ignore").strip()
        if decoded:
            log(f"  [NET] {decoded}")
            connections.append(decoded)
        idx = pos + 1

    out_path = os.path.join(OUTPUT_DIR, "netstat.txt")
    with open(out_path, "w") as f:
        f.write("\n".join(connections))
    log(f"  Saved connections -> {out_path}")


# ─────────────────────────────────────────
# STEP 5: Volatility 3 command reference
# ─────────────────────────────────────────
def print_vol3_commands(dump_path):
    log("\n[STEP 5] Real Volatility 3 Commands (run these on actual dump):")
    cmds = [
        f"python3 vol.py -f {dump_path} windows.info",
        f"python3 vol.py -f {dump_path} windows.pslist",
        f"python3 vol.py -f {dump_path} windows.pstree",
        f"python3 vol.py -f {dump_path} windows.cmdline",
        f"python3 vol.py -f {dump_path} windows.netstat",
        f"python3 vol.py -f {dump_path} windows.hashdump",
        f"python3 vol.py -f {dump_path} windows.malfind",
        f"python3 vol.py -f {dump_path} windows.dlllist",
    ]
    for c in cmds:
        log(f"  $ {c}")


# ─────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────
if __name__ == "__main__":
    setup()
    dump = create_demo_dump()
    hash_dump(dump)
    extract_strings(dump)
    simulate_pslist(dump)
    simulate_netstat(dump)
    print_vol3_commands(dump)

    log("\n" + "=" * 60)
    log("MEMORY ANALYSIS COMPLETE")
    log(f"All outputs saved in: {OUTPUT_DIR}/")
    log("=" * 60)
