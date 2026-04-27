#!/usr/bin/env python3
"""
Experiment 5: Metadata Extraction
Digital Forensics Lab
Extracts metadata from images (EXIF), PDFs, Office documents, and other files
"""

import os
import sys
import json
import struct
import hashlib
from datetime import datetime

OUTPUT_DIR  = "metadata_output"
LOG_FILE    = "metadata_log.txt"
REPORT_FILE = os.path.join(OUTPUT_DIR, "metadata_report.json")


def log(msg):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {msg}"
    print(line)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")


def setup():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    log("=" * 60)
    log("EXPERIMENT 5 – Metadata Extraction")
    log("=" * 60)


# ─────────────────────────────────────────
# CREATE DEMO FILES
# ─────────────────────────────────────────
def create_demo_files():
    log("[DEMO] Creating sample files for metadata extraction...")

    # Minimal JPEG with EXIF-like header
    jpeg_path = os.path.join(OUTPUT_DIR, "sample.jpg")
    with open(jpeg_path, "wb") as f:
        f.write(b"\xFF\xD8\xFF\xE1")  # SOI + APP1 marker
        exif_data = b"Exif\x00\x00II\x2A\x00"  # EXIF header
        f.write(struct.pack(">H", len(exif_data) + 2))
        f.write(exif_data)
        f.write(b"\xFF\xD9")  # EOI

    # Minimal PDF
    pdf_path = os.path.join(OUTPUT_DIR, "sample.pdf")
    with open(pdf_path, "w") as f:
        f.write("%PDF-1.4\n")
        f.write("1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")
        f.write("2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n")
        f.write("% Creator: Microsoft Word\n")
        f.write("% Author: John Doe\n")
        f.write("% CreationDate: D:20240315120000\n")
        f.write("%%EOF\n")

    # Simple TXT
    txt_path = os.path.join(OUTPUT_DIR, "sample.txt")
    with open(txt_path, "w") as f:
        f.write("This is a sample text file for forensic metadata extraction.\n")
        f.write("Author: Jane Smith\nCreated: 2024-03-15\n")

    log(f"  Created: {jpeg_path}, {pdf_path}, {txt_path}")
    return [jpeg_path, pdf_path, txt_path]


# ─────────────────────────────────────────
# BASIC FILESYSTEM METADATA
# ─────────────────────────────────────────
def get_fs_metadata(file_path):
    s = os.stat(file_path)
    return {
        "filename":       os.path.basename(file_path),
        "full_path":      os.path.abspath(file_path),
        "size_bytes":     s.st_size,
        "created":        datetime.fromtimestamp(s.st_ctime).strftime("%Y-%m-%d %H:%M:%S"),
        "modified":       datetime.fromtimestamp(s.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
        "accessed":       datetime.fromtimestamp(s.st_atime).strftime("%Y-%m-%d %H:%M:%S"),
        "permissions":    oct(s.st_mode),
        "md5":            compute_hash(file_path, "md5"),
        "sha256":         compute_hash(file_path, "sha256"),
    }


def compute_hash(file_path, algo="md5"):
    h = hashlib.new(algo)
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return "N/A"


# ─────────────────────────────────────────
# JPEG / EXIF METADATA (manual parsing)
# ─────────────────────────────────────────
def extract_jpeg_metadata(file_path):
    meta = {"type": "JPEG"}
    try:
        with open(file_path, "rb") as f:
            data = f.read()

        # Check for EXIF marker
        if b"Exif" in data:
            meta["has_exif"] = True
            meta["exif_offset"] = hex(data.find(b"Exif"))
        else:
            meta["has_exif"] = False

        # Try piexif if available
        try:
            import piexif
            exif_dict = piexif.load(file_path)
            for ifd in exif_dict:
                if isinstance(exif_dict[ifd], dict):
                    for tag, val in exif_dict[ifd].items():
                        try:
                            tag_name = piexif.TAGS[ifd].get(tag, {}).get("name", str(tag))
                            if isinstance(val, bytes):
                                val = val.decode("utf-8", errors="ignore").strip("\x00")
                            meta[f"exif_{tag_name}"] = str(val)
                        except Exception:
                            pass
        except ImportError:
            meta["note"] = "Install piexif for full EXIF: pip install piexif"

        # Try PIL for image dimensions
        try:
            from PIL import Image
            img = Image.open(file_path)
            meta["width"]  = img.width
            meta["height"] = img.height
            meta["mode"]   = img.mode
            meta["format"] = img.format
        except ImportError:
            meta["note2"] = "Install Pillow for dimensions: pip install Pillow"

    except Exception as e:
        meta["error"] = str(e)

    return meta


# ─────────────────────────────────────────
# PDF METADATA
# ─────────────────────────────────────────
def extract_pdf_metadata(file_path):
    meta = {"type": "PDF"}
    try:
        # Try PyPDF2 / pypdf
        try:
            import pypdf
            reader = pypdf.PdfReader(file_path)
            info = reader.metadata
            if info:
                for key, val in info.items():
                    meta[key.strip("/")] = str(val)
            meta["pages"] = len(reader.pages)
        except ImportError:
            pass

        # Manual scan for info keywords
        with open(file_path, "rb") as f:
            content = f.read().decode("utf-8", errors="ignore")

        for keyword in ["Author", "Creator", "Producer", "CreationDate", "ModDate", "Title", "Subject"]:
            idx = content.find(f"/{keyword}")
            if idx != -1:
                snippet = content[idx:idx+80].split("\n")[0]
                meta[f"manual_{keyword}"] = snippet.strip()

    except Exception as e:
        meta["error"] = str(e)

    return meta


# ─────────────────────────────────────────
# OFFICE DOCUMENT METADATA (docx/xlsx)
# ─────────────────────────────────────────
def extract_office_metadata(file_path):
    meta = {"type": "OFFICE"}
    try:
        import zipfile
        if zipfile.is_zipfile(file_path):
            with zipfile.ZipFile(file_path, "r") as z:
                meta["zip_contents"] = z.namelist()
                if "docProps/core.xml" in z.namelist():
                    core = z.read("docProps/core.xml").decode("utf-8", errors="ignore")
                    for tag in ["dc:creator", "cp:lastModifiedBy", "dcterms:created",
                                "dcterms:modified", "cp:revision"]:
                        start = core.find(f"<{tag}>")
                        end   = core.find(f"</{tag}>")
                        if start != -1 and end != -1:
                            meta[tag] = core[start+len(tag)+2:end]
                if "docProps/app.xml" in z.namelist():
                    app = z.read("docProps/app.xml").decode("utf-8", errors="ignore")
                    for tag in ["Application", "Company"]:
                        start = app.find(f"<{tag}>")
                        end   = app.find(f"</{tag}>")
                        if start != -1 and end != -1:
                            meta[tag] = app[start+len(tag)+2:end]
    except Exception as e:
        meta["error"] = str(e)
    return meta


# ─────────────────────────────────────────
# DISPATCH BY FILE TYPE
# ─────────────────────────────────────────
def extract_metadata(file_path):
    log(f"\n  Analyzing: {file_path}")
    result = get_fs_metadata(file_path)
    ext = os.path.splitext(file_path)[1].lower()

    if ext in (".jpg", ".jpeg"):
        result["file_metadata"] = extract_jpeg_metadata(file_path)
    elif ext == ".pdf":
        result["file_metadata"] = extract_pdf_metadata(file_path)
    elif ext in (".docx", ".xlsx", ".pptx"):
        result["file_metadata"] = extract_office_metadata(file_path)
    else:
        result["file_metadata"] = {"type": ext.upper() or "UNKNOWN"}

    for key, val in result.items():
        if key != "file_metadata":
            log(f"    {key:<20}: {val}")
    if "file_metadata" in result:
        for key, val in result["file_metadata"].items():
            log(f"    [meta] {key:<16}: {val}")

    return result


# ─────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────
if __name__ == "__main__":
    setup()

    # Use provided files or create demos
    if len(sys.argv) > 1:
        files = sys.argv[1:]
        log(f"Analyzing {len(files)} provided file(s)...")
    else:
        files = create_demo_files()

    all_results = []
    for f in files:
        if os.path.exists(f):
            all_results.append(extract_metadata(f))
        else:
            log(f"  [SKIP] File not found: {f}")

    with open(REPORT_FILE, "w") as f:
        json.dump(all_results, f, indent=2)

    log(f"\nReport saved -> {REPORT_FILE}")
    log("=" * 60)
    log("METADATA EXTRACTION COMPLETE")
    log("=" * 60)
