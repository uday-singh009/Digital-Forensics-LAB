# Experiment 2: Deleted File Recovery

## Aim
To recover deleted files from a disk image using file carving techniques and forensic tools such as Foremost and Scalpel.

## Theory
When a file is deleted, the operating system typically removes the directory entry and marks the file's clusters as available, but the actual data remains on disk until overwritten. File carving exploits this by scanning raw disk data for known file headers (magic bytes) and footers to reconstruct files without relying on the filesystem.

**Common file signatures:**
| File Type | Header (Hex) | Footer (Hex) |
|-----------|-------------|-------------|
| JPEG | FF D8 FF | FF D9 |
| PNG | 89 50 4E 47 | 49 45 4E 44 AE 42 60 82 |
| PDF | 25 50 44 46 | 25 25 45 4F 46 |
| ZIP/DOCX | 50 4B 03 04 | 50 4B 05 06 |

## Requirements
- Python 3.x
- Linux system
- `foremost` – `sudo apt install foremost`
- `scalpel` – `sudo apt install scalpel`
- A disk image file (`.dd`, `.img`, or `.raw`)

## Procedure

### Step 1: Prepare the disk image
If you have a real disk image from Experiment 1, copy it here. Otherwise the script creates a demo image automatically.

### Step 2: Run the recovery script
```bash
python3 recover_files.py
```
Set `DEMO_MODE = False` and update `IMAGE_FILE` to use your real disk image.

### Step 3: Examine recovered files
```bash
ls -lh recovered_files/
file recovered_files/*
```

### Step 4: Run Foremost manually (optional)
```bash
sudo foremost -t jpg,pdf,png -i disk_image.dd -o foremost_out/
cat foremost_out/audit.txt
```

### Step 5: Run Scalpel manually (optional)
```bash
sudo scalpel disk_image.dd -o scalpel_out/
```

## Expected Output
- `recovered_files/` — directory containing carved files
- `recovery_log.txt` — log with offsets, filenames, and MD5 hashes
- `demo_disk.dd` — (demo mode) sample image used

## Observations
| Method | Files Found | File Types | Notes |
|--------|------------|------------|-------|
| Manual Carving | | | |
| Foremost | | | |
| Scalpel | | | |

## Conclusion
Deleted file recovery was successfully performed using both manual file carving (Python) and automated tools. Files were identified by their magic bytes and extracted from the disk image.

## References
- Foremost documentation: `man foremost`
- Scalpel: https://github.com/sleuthkit/scalpel
- Carrier, B. (2005). *File System Forensic Analysis*
