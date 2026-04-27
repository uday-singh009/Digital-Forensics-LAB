# Experiment 5: Metadata Extraction

## Aim
To extract and analyze metadata from various file types (images, PDFs, Office documents) to gather forensic evidence such as author information, creation dates, GPS coordinates, and software details.

## Theory
Metadata is "data about data" — hidden information embedded within files that can reveal:
- **EXIF data** in JPEG images: camera model, GPS location, timestamp, software
- **PDF metadata**: author name, creation software, creation/modification dates
- **Office metadata**: author, company, revision count, last editor
- **Filesystem metadata**: MAC times, permissions, file size

Metadata is often overlooked by suspects and can be critical forensic evidence.

## Requirements
- Python 3.x
- Optional libraries (install for full functionality):
  ```bash
  pip install piexif Pillow pypdf
  ```
- `exiftool` for comprehensive extraction: `sudo apt install libimage-exiftool-perl`

## Procedure

### Step 1: Run the script
```bash
# Analyze demo files (auto-created)
python3 extract_metadata.py

# Analyze specific files
python3 extract_metadata.py photo.jpg document.pdf report.docx
```

### Step 2: Use ExifTool for comprehensive metadata
```bash
# Single file
exiftool photo.jpg

# All metadata in a directory
exiftool -r /path/to/folder/ > all_metadata.txt

# Export to CSV
exiftool -csv /path/to/folder/ > metadata.csv

# Extract GPS coordinates
exiftool -GPSLatitude -GPSLongitude photo.jpg
```

### Step 3: Remove metadata (sanitization awareness)
```bash
# Remove all metadata from image
exiftool -all= photo.jpg

# Remove metadata from PDF
exiftool -all= document.pdf
```

### Step 4: Office document metadata
```bash
# Extract from DOCX (it's a ZIP)
unzip -p document.docx docProps/core.xml | xmllint --format -
unzip -p document.docx docProps/app.xml | xmllint --format -
```

## Expected Output (`metadata_output/`)
| File | Description |
|------|-------------|
| `metadata_report.json` | Complete metadata for all analyzed files |
| `sample.jpg` | Demo JPEG file |
| `sample.pdf` | Demo PDF file |
| `sample.txt` | Demo text file |

## Sample EXIF Data Table
| Tag | Value | Forensic Significance |
|-----|-------|----------------------|
| Make | Apple Inc. | Device identification |
| DateTime | 2024:03:15 14:22:00 | Time of capture |
| GPSLatitude | 30.7333° N | Location evidence |
| Software | Photoshop CS6 | Tampering indicator |

## Observations
| File | Metadata Found | Forensic Notes |
|------|---------------|----------------|
| (record here) | | |

## Conclusion
Metadata was successfully extracted from multiple file types. The extracted data including creation dates, author names, and GPS coordinates provides valuable forensic evidence for investigations.

## References
- ExifTool: https://exiftool.org
- Phil Harvey, *ExifTool Documentation*
- Casey, E. (2011). *Digital Evidence and Computer Crime*
