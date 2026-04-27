#!/bin/bash
# =============================================================================
# Experiment 1: Disk Imaging using dd and dcfldd
# Digital Forensics Lab
# =============================================================================

echo "============================================"
echo " DIGITAL FORENSICS - EXPERIMENT 1"
echo " Disk Imaging & Verification"
echo "============================================"

# --- CONFIGURATION ---
SOURCE_DEVICE="/dev/sdb"         # Change to your source device
OUTPUT_IMAGE="disk_image.dd"
HASH_FILE="image_hash.txt"
LOG_FILE="imaging_log.txt"
BLOCK_SIZE="512"
DATE=$(date '+%Y-%m-%d %H:%M:%S')

echo "[*] Starting Disk Imaging at $DATE" | tee -a "$LOG_FILE"

# --- STEP 1: List available drives ---
echo ""
echo "[STEP 1] Available Block Devices:"
echo "--------------------------------------"
lsblk -o NAME,SIZE,TYPE,MOUNTPOINT,FSTYPE
echo ""

# --- STEP 2: Verify source device exists ---
echo "[STEP 2] Verifying source device: $SOURCE_DEVICE"
if [ ! -b "$SOURCE_DEVICE" ]; then
    echo "[WARNING] Device $SOURCE_DEVICE not found. Using a dummy file for demo."
    dd if=/dev/urandom of=dummy_source.img bs=1M count=10 2>/dev/null
    SOURCE_DEVICE="dummy_source.img"
    echo "[INFO] Created dummy_source.img (10MB) for demonstration."
fi

# --- STEP 3: Calculate pre-image hash (integrity baseline) ---
echo ""
echo "[STEP 3] Calculating source hash (MD5 + SHA256)..."
echo "--- Source Hash ($DATE) ---" >> "$HASH_FILE"

md5sum "$SOURCE_DEVICE" | tee -a "$HASH_FILE"
sha256sum "$SOURCE_DEVICE" | tee -a "$HASH_FILE"
echo "" >> "$HASH_FILE"

# --- STEP 4: Create disk image using dd ---
echo ""
echo "[STEP 4] Creating disk image with dd..."
echo "Source : $SOURCE_DEVICE"
echo "Output : $OUTPUT_IMAGE"
echo "Block  : $BLOCK_SIZE bytes"

dd if="$SOURCE_DEVICE" of="$OUTPUT_IMAGE" bs="$BLOCK_SIZE" conv=noerror,sync status=progress 2>&1 | tee -a "$LOG_FILE"

if [ $? -eq 0 ]; then
    echo "[SUCCESS] Disk image created: $OUTPUT_IMAGE"
else
    echo "[ERROR] dd command failed. Check log: $LOG_FILE"
    exit 1
fi

# --- STEP 5: Verify image integrity ---
echo ""
echo "[STEP 5] Verifying image integrity..."
echo "--- Image Hash ($DATE) ---" >> "$HASH_FILE"

md5sum "$OUTPUT_IMAGE" | tee -a "$HASH_FILE"
sha256sum "$OUTPUT_IMAGE" | tee -a "$HASH_FILE"

echo ""
echo "[STEP 6] Comparing source and image hashes..."
SRC_MD5=$(md5sum "$SOURCE_DEVICE" | awk '{print $1}')
IMG_MD5=$(md5sum "$OUTPUT_IMAGE" | awk '{print $1}')

if [ "$SRC_MD5" == "$IMG_MD5" ]; then
    echo "[VERIFIED] MD5 hashes MATCH. Image is forensically sound."
    echo "VERIFICATION: PASS - MD5 Match" >> "$LOG_FILE"
else
    echo "[MISMATCH] MD5 hashes DO NOT match!"
    echo "VERIFICATION: FAIL - MD5 Mismatch" >> "$LOG_FILE"
fi

# --- STEP 7: Display image info ---
echo ""
echo "[STEP 7] Image File Information:"
echo "--------------------------------------"
ls -lh "$OUTPUT_IMAGE"
file "$OUTPUT_IMAGE"

# --- STEP 8: Mount image read-only (optional) ---
echo ""
echo "[STEP 8] To mount image read-only:"
echo "  sudo mkdir -p /mnt/forensic"
echo "  sudo mount -o ro,loop $OUTPUT_IMAGE /mnt/forensic"
echo "  sudo umount /mnt/forensic   # to unmount"

echo ""
echo "============================================"
echo " IMAGING COMPLETE"
echo " Log saved to: $LOG_FILE"
echo " Hashes saved to: $HASH_FILE"
echo "============================================"
