# Experiment 1: Disk Imaging

## Aim
To create a forensic bit-by-bit copy (disk image) of a storage device and verify its integrity using hash values.

## Theory
Disk imaging is the first and most critical step in digital forensics. It involves creating an exact sector-by-sector copy of a storage medium so that the original evidence is preserved and all analysis is performed on the copy.

**Key tools used:**
- `dd` – standard Unix utility for low-level copying
- `dcfldd` – forensic version of dd with built-in hashing
- `md5sum` / `sha256sum` – for hash-based verification

## Requirements
- Linux system (Ubuntu/Kali recommended)
- `dd` (pre-installed) or `dcfldd` (`sudo apt install dcfldd`)
- Root/sudo privileges
- Source storage device (USB, HDD, etc.)

## Procedure

### Step 1: Identify the target device
```bash
lsblk
sudo fdisk -l
```

### Step 2: Run the imaging script
```bash
chmod +x disk_imaging.sh
sudo ./disk_imaging.sh
```
> Edit `SOURCE_DEVICE` variable in the script to point to your device (e.g., `/dev/sdb`)

### Step 3: Verify hash values
```bash
md5sum disk_image.dd
sha256sum disk_image.dd
```
Compare with values in `image_hash.txt`.

### Step 4: Mount image (read-only)
```bash
sudo mkdir -p /mnt/forensic
sudo mount -o ro,loop disk_image.dd /mnt/forensic
ls /mnt/forensic
sudo umount /mnt/forensic
```

## Expected Output
- `disk_image.dd` — forensic copy of the source device
- `image_hash.txt` — MD5 and SHA256 hashes of source and image
- `imaging_log.txt` — complete log of the imaging process

## Observations
| Parameter | Source | Image |
|-----------|--------|-------|
| MD5 Hash | (record here) | (record here) |
| SHA256 Hash | (record here) | (record here) |
| File Size | (record here) | (record here) |
| Verification | — | PASS / FAIL |

## Conclusion
A forensic disk image was successfully created using `dd`. The hash values of the source and image were compared and found to match, confirming the integrity of the acquired evidence.

## References
- `man dd`
- NIST SP 800-86: Guide to Integrating Forensic Techniques into Incident Response
- Brian Carrier, *File System Forensic Analysis*
