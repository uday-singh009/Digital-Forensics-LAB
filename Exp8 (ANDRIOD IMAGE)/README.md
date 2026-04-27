# Experiment 8: Android Forensics

## Aim
To perform forensic acquisition and analysis of an Android device using ADB (Android Debug Bridge) to extract SMS, call logs, contacts, application data, and other digital evidence.

## Theory
Android devices store evidence in:
- **SQLite databases** — SMS, calls, contacts, browser history, app data
- **Shared preferences** — App configuration, login tokens (XML)
- **File system** — Photos, downloads, documents
- **System logs** — logcat, crash reports

Key Android forensic artifacts:
| Artifact | Database | Table |
|----------|----------|-------|
| SMS/MMS | mmssms.db | sms, pdu |
| Call Logs | contacts2.db | calls |
| Contacts | contacts2.db | raw_contacts, data |
| Browser | browser.db | bookmarks, history |
| WhatsApp | msgstore.db | messages |

## Requirements
- Python 3.x
- ADB (Android Debug Bridge): `sudo apt install adb`
- Android device with **USB Debugging** enabled
- For rooted devices: `adb root` for full filesystem access

## Procedure

### Step 1: Enable USB Debugging on device
```
Settings → About Phone → Tap "Build Number" 7 times
Settings → Developer Options → Enable USB Debugging
```

### Step 2: Connect device and verify
```bash
adb devices
# Should show: <serial>  device
```

### Step 3: Run the forensics script
```bash
python3 android_forensics.py
```

### Step 4: Manual ADB commands
```bash
# Get device info
adb shell getprop ro.product.model
adb shell getprop ro.build.version.release

# List installed packages
adb shell pm list packages -f

# Pull SMS database (requires root or backup)
adb backup -noapk com.android.providers.telephony
# OR on rooted device:
adb root
adb pull /data/data/com.android.providers.telephony/databases/mmssms.db

# Read SMS
sqlite3 mmssms.db "SELECT address, datetime(date/1000,'unixepoch'), body, type FROM sms;"

# Read call logs
sqlite3 contacts2.db "SELECT number, datetime(date/1000,'unixepoch'), duration, type FROM calls;"

# Take screenshot
adb shell screencap -p /sdcard/screen.png
adb pull /sdcard/screen.png

# Record screen
adb shell screenrecord /sdcard/demo.mp4
adb pull /sdcard/demo.mp4

# Get all installed app info
adb shell dumpsys package | grep -E "Package|versionName"
```

### Step 5: Logical backup (without root)
```bash
# Create full device backup
adb backup -apk -shared -all -f backup.ab

# Convert backup to tar
dd if=backup.ab bs=24 skip=1 | python3 -c "import zlib,sys; sys.stdout.buffer.write(zlib.decompress(sys.stdin.buffer.read()))" > backup.tar
tar -xvf backup.tar
```

## Expected Output (`android_output/`)
| File | Description |
|------|-------------|
| `android_report.json` | Complete analysis report |
| `databases/mmssms.db` | Demo SMS database |
| `databases/calls.db` | Demo call log database |

## Observations
| Artifact | Count | Notable Findings |
|----------|-------|-----------------|
| SMS Messages | | |
| Call Logs | | |
| Installed Apps | | |
| Photos | | |

## Conclusion
Android forensic acquisition was performed using ADB. Key digital artifacts including SMS messages and call logs were successfully extracted and analyzed.

## References
- Android Debug Bridge: https://developer.android.com/studio/command-line/adb
- Andriller: https://andriller.com
- Oxygen Forensic Detective: https://www.oxygen-forensic.com
- NIST SP 800-101: Guidelines on Mobile Device Forensics
