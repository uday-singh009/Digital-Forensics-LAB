# 🔍 Digital Forensics Lab (COM-611)

## 👨‍💻 Student Details

* Name: Uday Veer
* Course: B.Tech CSE (Cyber Security)
* Semester: 6th
* Subject: Digital Forensics Lab

---

## 📌 Overview

This repository contains all **10 Digital Forensics Experiments** performed using tools like FTK Imager, Guymager, Autopsy, Sleuth Kit, Volatility, and other forensic utilities.

Digital Forensics involves identification, acquisition, analysis, and presentation of digital evidence for investigation purposes.

---

## 🧪 List of Experiments

| Exp No | Title                                     |
| ------ | ----------------------------------------- |
| 1      | Disk Imaging & Hash Verification          |
| 2      | Deleted File Recovery & Metadata Analysis |
| 3      | Memory Forensics using Volatility         |
| 4      | Timeline Analysis                         |
| 5      | Metadata Extraction                       |
| 6      | Email Investigation                       |
| 7      | Browser Forensics                         |
| 8      | Android Forensics                         |
| 9      | Hash Comparison                           |
| 10     | Incident Reconstruction                   |

---

# 🧪 Experiment 1: Disk Imaging & Hash Verification

## 🎯 Objective

To create a forensic disk image and verify integrity using SHA-256.

## 🛠 Tools

* FTK Imager / Guymager
* sha256sum

## ⚙️ Steps

1. Open FTK Imager / Guymager
2. Select storage device
3. Choose image format (RAW/E01)
4. Enable SHA-256 hashing
5. Start imaging process
6. Compare hash values

## ✅ Result

Disk image created successfully and hash values matched, confirming integrity.

---

# 🧪 Experiment 2: Deleted File Recovery

## 🎯 Objective

Recover deleted files and analyze metadata.

## 🛠 Tools

* Autopsy
* Sleuth Kit

## ⚙️ Steps

1. Open Autopsy
2. Create new case
3. Add disk image
4. Analyze data source
5. Navigate to deleted files
6. Extract recovered files
7. View metadata

## ✅ Result

Deleted files recovered and metadata analyzed successfully.

---

# 🧪 Experiment 3: Memory Forensics

## 🎯 Objective

Capture and analyze RAM.

## 🛠 Tools

* LiME / DumpIt
* Volatility

## ⚙️ Steps

1. Capture RAM image
2. Load memory image in Volatility
3. Extract processes
4. Analyze network connections

## ✅ Result

Running processes and system activities extracted from memory.

---

# 🧪 Experiment 4: Timeline Analysis

## 🎯 Objective

Generate system timeline.

## 🛠 Tools

* Plaso (log2timeline)

## ⚙️ Steps

1. Create timeline using log2timeline
2. Convert to readable format
3. Analyze timestamps

## ✅ Result

System activity timeline generated successfully.

---

# 🧪 Experiment 5: Metadata Extraction

## 🎯 Objective

Extract metadata from files.

## 🛠 Tools

* ExifTool
* PDFinfo

## ⚙️ Steps

1. Run ExifTool on image
2. Run PDFinfo on documents
3. Analyze metadata

## ✅ Result

Metadata such as timestamps and author extracted successfully.

---

# 🧪 Experiment 6: Email Investigation

## 🎯 Objective

Analyze email headers.

## 🛠 Tools

* Mozilla Thunderbird
* GPG tools

## ⚙️ Steps

1. Configure email accounts
2. Send and receive emails
3. View email source
4. Analyze headers

## ✅ Result

Email sender details and routing information identified.

---

# 🧪 Experiment 7: Browser Forensics

## 🎯 Objective

Analyze browsing history.

## 🛠 Tools

* Browser History Examiner / SQLite DB Browser

## ⚙️ Steps

1. Open browser database
2. Analyze history file
3. Extract URLs and timestamps

## ✅ Result

User browsing activity successfully analyzed.

---

# 🧪 Experiment 8: Android Forensics

## 🎯 Objective

Analyze Android device data.

## 🛠 Tools

* Andriller / Autopsy

## ⚙️ Steps

1. Load Android image
2. Extract SMS, call logs
3. Analyze app data

## ✅ Result

Mobile data including messages and logs extracted.

---

# 🧪 Experiment 9: Hash Comparison

## 🎯 Objective

Verify file integrity using hashing.

## 🛠 Tools

* sha256sum
* md5deep

## ⚙️ Steps

1. Generate hash of file
2. Compare with another file
3. Check integrity

## ✅ Result

File integrity verified successfully.

---

# 🧪 Experiment 10: Incident Reconstruction

## 🎯 Objective

Reconstruct events using logs.

## 🛠 Tools

* System logs
* Timesketch (optional)

## ⚙️ Steps

1. Collect logs
2. Analyze events
3. Create timeline
4. Identify suspicious activity

## ✅ Result

Incident reconstructed successfully.

---

# 🧰 Tools Used

* FTK Imager
* Guymager
* Autopsy
* Sleuth Kit
* Volatility
* ExifTool
* Thunderbird
* sha256sum / md5deep

---

# 📊 Conclusion

All experiments were successfully performed, demonstrating practical knowledge of digital forensic techniques including disk imaging, file recovery, memory analysis, and incident investigation.

---

# 🚀 Future Scope

* Advanced malware analysis
* Cloud forensics
* AI-based forensic automation
* Mobile and IoT forensics

---
