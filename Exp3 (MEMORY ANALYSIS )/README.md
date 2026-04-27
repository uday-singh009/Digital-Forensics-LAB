# Experiment 3: RAM Capture and Memory Analysis

## Aim
To capture a live memory dump from a system and analyze it using Volatility 3 to extract running processes, network connections, and other volatile artifacts.

## Theory
RAM (volatile memory) contains crucial forensic artifacts that disappear when a system is powered off. Memory forensics can reveal:
- Running and hidden processes
- Active network connections
- Encryption keys and passwords
- Injected malicious code (malfind)
- Loaded DLLs and kernel modules

## Requirements
- Python 3.x
- Volatility 3: https://github.com/volatilityfoundation/volatility3
- LiME (Linux Memory Extractor) for live capture (Linux): `sudo apt install lime-forensics-dkms`
- WinPmem / DumpIt for Windows live capture
- A memory dump file (`.raw`, `.vmem`, `.mem`)

## Procedure

### Step 1: Capture live memory (Linux)
```bash
# Load LiME module
sudo insmod lime.ko "path=/media/usb/memory.lime format=lime"
```

### Step 2: Capture live memory (Windows)
```
# Run DumpIt.exe as Administrator
DumpIt.exe /output memory.raw
```

### Step 3: Run this script (demo/simulation)
```bash
python3 memory_analysis.py
```

### Step 4: Run real Volatility 3 analysis
```bash
# Install Volatility 3
git clone https://github.com/volatilityfoundation/volatility3
cd volatility3
pip install -r requirements.txt

# Identify OS profile
python3 vol.py -f memory.raw windows.info

# List processes
python3 vol.py -f memory.raw windows.pslist

# Process tree
python3 vol.py -f memory.raw windows.pstree

# Network connections
python3 vol.py -f memory.raw windows.netstat

# Extract password hashes
python3 vol.py -f memory.raw windows.hashdump

# Find injected code
python3 vol.py -f memory.raw windows.malfind
```

### Step 5: Extract strings
```bash
strings -a -n 8 memory.raw > strings.txt
grep -i "password\|http\|login" strings.txt
```

## Expected Output (in `memory_output/`)
- `dump_hashes.txt` — MD5/SHA1 of dump
- `pslist.json` — extracted process list
- `netstat.txt` — network connections
- `strings.txt` — printable strings

## Observations Table
| Plugin | Finding | Notes |
|--------|---------|-------|
| windows.pslist | | |
| windows.netstat | | |
| windows.malfind | | |
| windows.hashdump | | |

## Conclusion
RAM analysis was performed using Volatility 3 and manual string extraction. Running processes, network connections, and suspicious artifacts were successfully identified from the memory dump.

## References
- Volatility Foundation: https://github.com/volatilityfoundation/volatility3
- Ligh, M. H. et al. *The Art of Memory Forensics* (2014)
- LiME: https://github.com/504ensicsLabs/LiME
