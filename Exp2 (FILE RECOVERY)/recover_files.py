#!/usr/bin/env python3
"""
Experiment 2: Deleted File Recovery
Digital Forensics Lab
Uses: Scalpel / Foremost / PhotoRec (via subprocess) + manual carving demo
"""

import os
import sys
import subprocess
import hashlib
import shutil
from datetime import datetime

# ─────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────
IMAGE_FILE   = "disk_image.dd"       # Change to your disk image path
OUTPUT_DIR   = "recovered_files"
LOG_FILE     = "recovery_log.txt"
DEMO_MODE    = True                  # Set False when using a real disk image

# File signatures (magic bytes) for manual carving
FILE_SIGNATURES = {
    "jpg":  (b"\xFF\xD8\xFF",        b"\xFF\xD9"),
    "png":  (b"\x89PNG\r\n\x1a\n",  b"\x00\x00\x00\x00IEND\xaeB`\x82"),
    "pdf":  (b"%PDF",                b"%%EOF"),
    "zip":  (b"PK\x03\x04",         b"PK\x05\x06"),
    "gif":  (b"GIF8",                b"\x00;"),
    "docx": (b"PK\x03\x04",         b""),   # Same as ZIP
    "mp3":  (b"\xFF\xFB",            b""),
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
    log("EXPERIMENT 2 – Deleted File Recovery")
    log("=" * 60)


# ─────────────────────────────────────────
# DEMO: Create a sample image with embedded files
# ─────────────────────────────────────────
def create_demo_image():
    log("[DEMO] Creating sample disk image with embedded files...")
    demo_img = "demo_disk.dd"

    with open(demo_img, "wb") as f:
        # Write padding
        f.write(b"\x00" * 1024)

        # Embed fake JPEG
        f.write(b"\xFF\xD8\xFF\xE0" + b"FAKE_JPEG_CONTENT_12345" + b"\xFF\xD9")
        f.write(b"\x00" * 512)

        # Embed fake PDF
        f.write(b"%PDF-1.4\n%Fake PDF content for forensics demo\n")
        f.write(b"\n%%EOF")
        f.write(b"\x00" * 512)

        # Embed fake PNG
        f.write(b"\x89PNG\r\n\x1a\nFAKE_PNG_DATA" + b"\x00" * 100 + b"\x00\x00\x00\x00IEND\xaeB`\x82")
        f.write(b"\x00" * 256)

    log(f"[DEMO] Created: {demo_img}")
    return demo_img


# ─────────────────────────────────────────
# METHOD 1: Manual File Carving
# ─────────────────────────────────────────
def manual_carve(image_path):
    log(f"\n[METHOD 1] Manual File Carving on: {image_path}")
    recovered = []

    try:
        with open(image_path, "rb") as f:
            data = f.read()
    except FileNotFoundError:
        log(f"[ERROR] Image not found: {image_path}")
        return []

    for ext, (header, footer) in FILE_SIGNATURES.items():
        start = 0
        count = 0
        while True:
            idx = data.find(header, start)
            if idx == -1:
                break

            end = data.find(footer, idx + len(header)) if footer else idx + 1024
            if end == -1:
                end = idx + 2048  # fallback size
            else:
                end += len(footer)

            carved_data = data[idx:end]
            fname = os.path.join(OUTPUT_DIR, f"carved_{ext}_{count:03d}.{ext}")
            with open(fname, "wb") as out:
                out.write(carved_data)

            file_hash = hashlib.md5(carved_data).hexdigest()
            log(f"  [FOUND] {ext.upper()} at offset {idx:#010x} -> {fname} (MD5: {file_hash})")
            recovered.append(fname)
            count += 1
            start = end

        if count:
            log(f"  [TOTAL] {count} {ext.upper()} file(s) recovered")

    return recovered


# ─────────────────────────────────────────
# METHOD 2: Foremost (if installed)
# ─────────────────────────────────────────
def run_foremost(image_path):
    log(f"\n[METHOD 2] Attempting Foremost on: {image_path}")
    foremost_out = os.path.join(OUTPUT_DIR, "foremost_output")

    if shutil.which("foremost") is None:
        log("  [SKIP] foremost not installed. Install: sudo apt install foremost")
        return

    cmd = ["foremost", "-t", "jpg,pdf,png,gif,zip", "-i", image_path, "-o", foremost_out]
    log(f"  CMD: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    log(f"  STDOUT: {result.stdout.strip()}")
    if result.returncode == 0:
        log(f"  [SUCCESS] Foremost output saved to: {foremost_out}")
    else:
        log(f"  [WARN] Foremost returned: {result.returncode}")


# ─────────────────────────────────────────
# METHOD 3: Scalpel (if installed)
# ─────────────────────────────────────────
def run_scalpel(image_path):
    log(f"\n[METHOD 3] Attempting Scalpel on: {image_path}")
    scalpel_out = os.path.join(OUTPUT_DIR, "scalpel_output")

    if shutil.which("scalpel") is None:
        log("  [SKIP] scalpel not installed. Install: sudo apt install scalpel")
        return

    cmd = ["scalpel", image_path, "-o", scalpel_out]
    log(f"  CMD: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode == 0:
        log(f"  [SUCCESS] Scalpel output in: {scalpel_out}")
    else:
        log(f"  [WARN] Scalpel stderr: {result.stderr.strip()[:200]}")


# ─────────────────────────────────────────
# REPORT
# ─────────────────────────────────────────
def generate_report(recovered_files):
    log("\n" + "=" * 60)
    log("RECOVERY REPORT")
    log("=" * 60)
    log(f"Total files recovered: {len(recovered_files)}")
    for f in recovered_files:
        size = os.path.getsize(f) if os.path.exists(f) else 0
        log(f"  {f}  ({size} bytes)")
    log(f"\nFull log saved to: {LOG_FILE}")
    log("=" * 60)


# ─────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────
if __name__ == "__main__":
    setup()

    # Determine image path
    if DEMO_MODE or not os.path.exists(IMAGE_FILE):
        image_path = create_demo_image()
    else:
        image_path = IMAGE_FILE
        log(f"[INFO] Using existing image: {image_path}")

    # Run recovery methods
    recovered = manual_carve(image_path)
    run_foremost(image_path)
    run_scalpel(image_path)

    # Final report
    generate_report(recovered)
