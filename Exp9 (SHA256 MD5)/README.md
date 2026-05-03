# 🧪 Experiment 09: Hash-Based File Comparison & Integrity Verification

## 🎯 Objective

To generate and compare cryptographic hash values (SHA-256 and MD5) to verify file integrity and detect any modifications.

---

## 🛠 Tools Used

* sha256sum
* md5deep

---

## ⚙️ Procedure

### Step 1: Select Files

Choose two files:

* Original file
* Copied/modified file

---

### Step 2: Generate SHA-256 Hash

```bash
sha256sum file1.txt
sha256sum file2.txt
```

---

### Step 3: Compare Hash Values

* If hashes match → files are identical
* If hashes differ → file has been modified

---

### Step 4: Generate MD5 Hash (Optional)

```bash
md5deep file1.txt
md5deep file2.txt
```

---

### Step 5: Folder Hashing (Optional)

```bash
md5deep -r folder/
```

---

## 📸 Screenshots

![SHA256 Output](screenshots/hash1.png)
![MD5 Output](screenshots/hash2.png)

---

## 📊 Result

Hash values were successfully generated for selected files. Matching hashes confirmed file integrity, while differences indicated modification.

---

## 🧠 Conclusion

Hashing is an essential technique in digital forensics to ensure data integrity and detect tampering.

---
