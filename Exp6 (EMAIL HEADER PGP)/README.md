# Experiment 6: Email Forensics

## Aim
To analyze email messages for forensic evidence, including header analysis, routing path tracing, spoofing detection, attachment examination, and URL extraction.

## Theory
Email forensics involves examining email messages to determine their authenticity, origin, and content. Key areas of analysis include:

- **Email Headers**: Contain routing information, sender details, timestamps
- **Received Headers**: Show the path an email traveled (read bottom-to-top)
- **Spoofing Detection**: Comparing From, Reply-To, and Return-Path domains
- **Attachments**: Can contain malware; require hash analysis
- **URLs**: May point to phishing sites or C2 servers

**Email Header Fields:**
| Field | Forensic Significance |
|-------|----------------------|
| From | Claimed sender (can be spoofed) |
| Received | Actual routing hops (harder to fake) |
| X-Originating-IP | Original sender IP |
| Message-ID | Unique identifier |
| Return-Path | Bounce address (often reveals true origin) |

## Requirements
- Python 3.x (standard library only for core features)
- Optional: `pip install requests` for IP geolocation

## Procedure

### Step 1: Run the script
```bash
# Analyze built-in sample phishing email
python3 email_forensics.py

# Analyze your own .eml file
python3 email_forensics.py /path/to/email.eml
```

### Step 2: Manual header analysis
To get email headers from Gmail: Open email → More (⋮) → Show original  
To get from Outlook: File → Properties → Internet Headers

```bash
# Analyze headers online
# https://mxtoolbox.com/EmailHeaders.aspx
# https://toolbox.googleapps.com/apps/messageheader/
```

### Step 3: Trace the email path
Read `Received` headers from **bottom to top** to trace the route.
```
Hop 1 (origin): "from [attacker IP]"
Hop 2: "from attacker mail server"
Hop 3 (destination): "by victim mail server"
```

### Step 4: Check for spoofing
```bash
# Check SPF record
nslookup -type=TXT example.com

# Check DKIM record
nslookup -type=TXT default._domainkey.example.com

# Check DMARC
nslookup -type=TXT _dmarc.example.com
```

### Step 5: Examine attachments safely
```bash
# NEVER open suspicious attachments directly!
# Check hash against VirusTotal
sha256sum attachment.exe
# Submit hash at: https://www.virustotal.com
```

## Expected Output (`email_output/`)
| File | Description |
|------|-------------|
| `email_report.json` | Complete forensic report |
| `attachment_*` | Extracted attachments (if any) |

## Sample Findings Table
| Finding | Value | Suspicious? |
|---------|-------|-------------|
| From domain | example.com | No |
| Reply-To domain | other.net | YES – mismatch |
| X-Originating-IP | 185.220.101.45 | Check geolocation |
| Attachment type | .exe | YES – executable |
| URL found | http://phish.attacker.ru | YES |

## Observations
| Parameter | Value | Notes |
|-----------|-------|-------|
| Routing hops | | |
| Spoofing detected | Yes/No | |
| Attachment found | Yes/No | |
| Malicious URLs | Yes/No | |

## Conclusion
Email headers were successfully analyzed to trace the routing path, detect spoofing attempts, and identify malicious attachments and URLs. The analysis reveals key forensic artifacts that can aid in attribution.

## References
- RFC 5321: Simple Mail Transfer Protocol
- RFC 7208: SPF
- MXToolbox: https://mxtoolbox.com
- PhishTank: https://www.phishtank.com
