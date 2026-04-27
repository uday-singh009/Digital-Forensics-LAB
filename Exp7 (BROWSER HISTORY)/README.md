# Experiment 7: Browser Forensics

## Aim
To extract and analyze forensic artifacts from web browsers including browsing history, cookies, downloaded files, and cached data to reconstruct a user's online activity.

## Theory
Modern browsers store extensive activity data in SQLite databases. Key artifacts include:

| Artifact | Location | Forensic Value |
|----------|----------|----------------|
| History | `History` (SQLite) | URLs visited, timestamps |
| Downloads | `History` (SQLite) | Downloaded files, sources |
| Cookies | `Cookies` (SQLite) | Session tokens, login evidence |
| Cache | `Cache/` directory | Webpage content |
| Form data | `Web Data` (SQLite) | Autofill, typed data |
| Bookmarks | `Bookmarks` (JSON) | User interests |
| Passwords | `Login Data` (SQLite, encrypted) | Saved credentials |

**Chrome timestamps** use WebKit format: microseconds since Jan 1, 1601.  
**Firefox timestamps** use Unix microseconds: microseconds since Jan 1, 1970.

## Requirements
- Python 3.x (standard library only)
- SQLite3 (built into Python)
- Access to browser profile directories

## Procedure

### Step 1: Run the script (demo mode)
```bash
python3 browser_forensics.py
```

### Step 2: Analyze real browser data
Edit the script and point `history_db` to the real Chrome/Firefox database:

**Linux (Chrome):**
```bash
cp ~/.config/google-chrome/Default/History /tmp/History_copy
python3 browser_forensics.py  # update path in script
```

**Windows (Chrome) — run as admin:**
```
%LOCALAPPDATA%\Google\Chrome\User Data\Default\History
```

### Step 3: Direct SQLite queries
```bash
# Open Chrome history directly
sqlite3 History

# List all visited URLs
sqlite3 History "SELECT url, title, visit_count FROM urls ORDER BY visit_count DESC LIMIT 20;"

# Recent downloads
sqlite3 History "SELECT current_path, total_bytes, tab_url FROM downloads;"

# All cookies
sqlite3 Cookies "SELECT host_key, name, last_access_utc FROM cookies ORDER BY last_access_utc DESC;"
```

### Step 4: Firefox
```bash
# Firefox uses places.sqlite
sqlite3 places.sqlite "SELECT url, visit_count, last_visit_date FROM moz_places ORDER BY last_visit_date DESC LIMIT 20;"
```

## Expected Output (`browser_output/`)
| File | Description |
|------|-------------|
| `browser_report.json` | Complete analysis |
| `demo_chrome/History` | Sample Chrome SQLite DB |
| `demo_chrome/Cookies` | Sample cookies SQLite DB |

## Observations
| Artifact | Count Found | Notable Findings |
|----------|------------|-----------------|
| History entries | | |
| Downloads | | |
| Suspicious downloads | | |
| Cookies | | |

## Conclusion
Browser forensics revealed a complete record of the user's online activity. Suspicious downloads and session cookies were identified and documented.

## References
- Digital Corpora: https://digitalcorpora.org
- SQLite Browser: https://sqlitebrowser.org
- Zammetti, F. *Practical Web 2.0 Applications with PHP*
