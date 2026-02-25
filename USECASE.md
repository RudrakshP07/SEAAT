# 📖 SEAAT v2.0 — Use Case Guide
### Security Event Analysis & Automation Tool
> Complete usage reference with real-world scenarios and expected outputs for every menu option.

---

## 📌 Table of Contents

1. [Option 1 — Reputation / Blocklist Check](#option-1--reputation--blocklist-check)
2. [Option 2 — DNS / WHOIS Lookup](#option-2--dns--whois-lookup)
3. [Option 3 — Email Security & Phishing Analysis](#option-3--email-security--phishing-analysis)
4. [Option 4 — URL Decoding & Investigation](#option-4--url-decoding--investigation)
5. [Option 5 — File Sandbox & Static Analysis](#option-5--file-sandbox--static-analysis)
6. [Option 6 — IOC Sanitization](#option-6--ioc-sanitization)
7. [Option 7 — Brand Monitoring & Analysis](#option-7--brand-monitoring--analysis)
8. [Option 8 — IOC Extractor](#option-8--ioc-extractor)
9. [Option 9 — Threat Intelligence Correlation](#option-9--threat-intelligence-correlation)
10. [Option 10 — Network Analysis & Pivot](#option-10--network-analysis--pivot)
11. [Option 11 — Case Manager](#option-11--case-manager)
12. [Option 12 — SIEM / SOAR Toolbox](#option-12--siem--soar-toolbox)
13. [Option C — Help & Configuration](#option-c--help--configuration)

---

## Launching SEAAT

```
python main.py
```

**Expected Output:**
```
  ██████╗ ███████╗ █████╗  █████╗ ████████╗
 ██╔════╝ ██╔════╝██╔══██╗██╔══██╗╚══██╔══╝
 ╚█████╗  █████╗  ███████║███████║   ██║
  ╚═══██╗ ██╔══╝  ██╔══██║██╔══██║   ██║
 ██████╔╝ ███████╗██║  ██║██║  ██║   ██║
 ╚═════╝  ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝

  ══════════════════════════════════════════════════════
  Security Event Analysis & Automation Tool
  SOC Analyst's Unified Threat Investigation Platform
  v2.0 | Dept. of CSE - Cyber Security | AITR, Indore
  ══════════════════════════════════════════════════════

  [*] Session started: Wednesday, 25 February 2026  |  03:39:26

  ┌─────────────────────────────────────────────────────────┐
  │              MAIN INVESTIGATION MENU                   │
  └─────────────────────────────────────────────────────────┘

  ── THREAT INTELLIGENCE ─────────────────────────────────
  [ 1] Reputation / Blocklist Check      IPs · Domains · URLs · Hashes
  [ 2] DNS / WHOIS Lookup                Reverse DNS · Records · ISP · WHOIS
  [ 9] Threat Intelligence Correlation   OTX · ThreatFox · MITRE ATT&CK
  [10] Network Analysis & Pivot          ASN · Infra Map · Shodan · GreyNoise
  ...

[SEAAT]> Select Option:
```

> **First Run:** If no API keys are configured, SEAAT automatically redirects you to the Configuration menu before showing the main menu.

---

## Option 1 — Reputation / Blocklist Check

**Purpose:** Check if an IP, domain, URL, or file hash is malicious across VirusTotal, AbuseIPDB, AlienVault OTX, and APIVoid.

**When to use:**
- A firewall alert triggers on an outbound connection — check the destination IP
- A user reports a suspicious email link — check the URL
- Antivirus flags a file — check the hash
- An alert mentions an unknown domain — check the domain

---

### Sub-option 1 — Single IOC Check

**Input:**
```
[SEAAT]> Select Option: 1

  ╔════════════════════════════════════════════════════════════╗
  ║              REPUTATION / BLOCKLIST CHECK                  ║
  ╚════════════════════════════════════════════════════════════╝

  [1] Single IOC Check
  [2] Bulk Check (from file)
  [0] Back

  Select: 1

  Enter IP / Domain / URL / Hash: 185.220.101.45
```

**Expected Output:**
```
  [*] Detected type: IP
  [*] Querying threat intelligence sources...

  ────────────────────────────────────────────────────────────
  IOC        : 185.220.101.45
  Type       : IP
  Risk Score : 87/100  [CRITICAL]
  ────────────────────────────────────────────────────────────

  [ VirusTotal ]
      Malicious Detections:       14
      Suspicious:                 2
      Harmless:                   52
      Reputation Score:           -85

  [ AbuseIPDB ]
      Abuse Score:                97
      Country:                    DE
      ISP:                        Frantech Solutions
      Total Reports:              1842
      Last Reported:              2026-02-24T18:22:11+00:00

  [ AlienVault OTX ]
      Pulse Count:                23
      Tags:                       tor, exit-node, scanning, malicious, c2

  ────────────────────────────────────────────────────────────
```

---

**Input for a Domain:**
```
  Enter IP / Domain / URL / Hash: malware-c2.xyz
```

**Expected Output:**
```
  [*] Detected type: DOMAIN
  [*] Querying threat intelligence sources...

  ────────────────────────────────────────────────────────────
  IOC        : malware-c2.xyz
  Type       : DOMAIN
  Risk Score : 72/100  [HIGH]
  ────────────────────────────────────────────────────────────

  [ VirusTotal ]
      Malicious Detections:       9
      Suspicious:                 3
      Harmless:                   20
      Reputation Score:           -60

  [ AlienVault OTX ]
      Pulse Count:                7
      Tags:                       malware, c2, dropper

  [ APIVoid ]
      Blacklists Detected:        6
      Blacklists Checked:         40
      Is Risky:                   True

  ────────────────────────────────────────────────────────────
```

---

**Input for a Hash:**
```
  Enter IP / Domain / URL / Hash: 44d88612fea8a8f36de82e1278abb02f
```

**Expected Output:**
```
  [*] Detected type: HASH
  [*] Querying threat intelligence sources...

  ────────────────────────────────────────────────────────────
  IOC        : 44d88612fea8a8f36de82e1278abb02f
  Type       : HASH
  Risk Score : 45/100  [MEDIUM]
  ────────────────────────────────────────────────────────────

  [ VirusTotal ]
      Malicious Detections:       32
      Suspicious:                 4
      Harmless:                   0
      VT File Type:               Win32 EXE
      VT Tags:                    trojan, rat, upx

  [ AlienVault OTX ]
      Pulse Count:                3
      Tags:                       AgentTesla, rat, stealer

  ────────────────────────────────────────────────────────────
```

---

### Sub-option 2 — Bulk Check from File

**Use case:** You have a list of 50 IOCs from a SIEM alert. Check them all at once.

**Prepare file** (`iocs.txt`):
```
185.220.101.45
malware-c2.xyz
http://phish.example.com/login
44d88612fea8a8f36de82e1278abb02f
203.0.113.99
```

**Input:**
```
  Select: 2
  Enter file path (one IOC per line): /home/analyst/iocs.txt
```

**Expected Output:**
```
  [*] Loaded 5 IOCs from file

  ════════════════════════════════════════════════════════════
  IOC        : 185.220.101.45
  Type       : IP
  Risk Score : 87/100  [CRITICAL]
  ...

  ════════════════════════════════════════════════════════════
  IOC        : malware-c2.xyz
  Type       : DOMAIN
  Risk Score : 72/100  [HIGH]
  ...
```

> **Risk Score Guide:**
> | Score | Label | Meaning |
> |-------|-------|---------|
> | 75–100 | CRITICAL | Block immediately, escalate |
> | 50–74 | HIGH | Very likely malicious |
> | 25–49 | MEDIUM | Suspicious, investigate further |
> | 10–24 | LOW | Minor indicators, monitor |
> | 0–9 | CLEAN | No significant findings |

---

## Option 2 — DNS / WHOIS Lookup

**Purpose:** Investigate domains and IPs at the DNS/infrastructure level. Essential for understanding who owns a domain, how long it has existed, and what records it exposes.

---

### Sub-option 1 — Reverse DNS Lookup

**When to use:** You have a suspicious IP from firewall logs and want to know what hostname it maps to.

**Input:**
```
[SEAAT]> Select Option: 2
  Select: 1
  Enter IP address: 8.8.8.8
```

**Expected Output:**
```
  [*] Performing reverse DNS for 8.8.8.8...
      Hostname:                   dns.google
      Aliases:                    None
```

---

### Sub-option 2 — DNS Record Lookup

**When to use:** Investigate what records a suspicious domain exposes — mail servers, IPs, nameservers.

**Input:**
```
  Select: 2
  Enter domain: suspiciousdomain.ru
```

**Expected Output:**
```
  [*] DNS lookup for: suspiciousdomain.ru
      A Record:                   192.168.99.1
      MX Record:                  mail.suspiciousdomain.ru
      NS Record:                  ns1.shady-registrar.com
      TXT Record:                 v=spf1 include:spf.suspiciousdomain.ru ~all
      CNAME Record:               Not found
```

---

### Sub-option 3 — WHOIS Lookup

**When to use:** Check domain registration age, registrar, and owner details. Newly registered domains are a major phishing/malware red flag.

**Input:**
```
  Select: 3
  Enter domain: suspiciousdomain.ru
```

**Expected Output:**
```
  [*] WHOIS lookup for: suspiciousdomain.ru
      Registrar:                  Namecheap, Inc.
      Created Date:               2026-02-20 04:11:00
      Expiry Date:                2027-02-20 04:11:00
      Updated Date:               2026-02-20 04:11:00
      Name Servers:               ns1.shady-registrar.com
      WHOIS Status:               clientTransferProhibited
      Registrant Org:             Privacy Protection
      Registrant Country:         RU
      Domain Age:                 5 days

  [!] Domain is only 5 days old - SUSPICIOUS!
```

> **Key indicator:** Domains less than 30 days old used in security incidents are almost always malicious infrastructure.

---

### Sub-option 4 — ISP / GeoIP Lookup

**When to use:** Determine the geographic origin and hosting provider of a suspicious IP.

**Input:**
```
  Select: 4
  Enter IP address: 45.142.212.100
```

**Expected Output:**
```
  [*] ISP/GeoIP lookup for: 45.142.212.100
      Org:                        AS206728 Media Land LLC
      Country:                    RU
      Region:                     Moscow
      City:                       Moscow
      Hostname:                   Not available
      Timezone:                   Europe/Moscow
```

---

### Sub-option 5 — SPF / DKIM / DMARC Check

**When to use:** Verify if a domain has proper email authentication configured. Missing or weak records make a domain easy to spoof.

**Input:**
```
  Select: 5
  Enter domain: targetcompany.com
```

**Expected Output:**
```
  [*] Checking email security records for: targetcompany.com
      SPF Record:                 v=spf1 include:_spf.google.com ~all
      DMARC Record:               v=DMARC1; p=reject; rua=mailto:dmarc@targetcompany.com
      DKIM (google):              v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0B...
```

**Expected Output (missing records — spoofable domain):**
```
  [!] No SPF record found
  [!] No DMARC record found
  [!] No DKIM record found
```

> **Note:** If a domain has no DMARC or SPF, attackers can send emails that appear to come from that domain with no technical barrier.

---

### Sub-option 6 — Fast-Flux Detection

**When to use:** Detecting botnet infrastructure. Botnets use fast-flux DNS to rapidly rotate IPs under a single domain to avoid takedown.

**Input:**
```
  Select: 6
  Enter domain: botnet-c2.example.com
```

**Expected Output (fast-flux detected):**
```
  [*] Fast-flux detection for: botnet-c2.example.com
      A Records Found:            8
      TTL (seconds):              60

  [!] Multiple A records detected - possible fast-flux
  [!] Very low TTL (60s) - possible fast-flux or CDN
```

**Expected Output (clean):**
```
      A Records Found:            1
      TTL (seconds):              3600
  [+] No fast-flux indicators detected
```

---

## Option 3 — Email Security & Phishing Analysis

**Purpose:** End-to-end phishing email investigation — from verifying the sender's email address to analyzing raw headers, detecting BEC patterns, and checking phishing landing pages.

---

### Sub-option 1 — Email Address Verification & Temp-Mail Check

**When to use:** A suspicious email arrives from an unknown address. Before anything else, verify if the address is real, disposable, or from a malicious domain.

**Input:**
```
[SEAAT]> Select Option: 3
  Select: 1
  Enter email address: hiyito7664@kaoing.com
```

**Expected Output (temp/disposable email):**
```
  [*] Verifying email: hiyito7664@kaoing.com
  [!] DISPOSABLE EMAIL: 'kaoing.com' is a known temp-mail domain

  [*] Checking MX records...
  [!] No MX records found - domain may not accept email

  [*] Probing domain HTTP status...
      HTTP Status:                200
      Server:                     nginx
      Final URL:                  https://kaoing.com/

  [*] Querying APIVoid email verification...
      Is Disposable:              True
      Is Free Provider:           False
      Has Valid MX:               False
      Role Address:               False
```

**Expected Output (legitimate email):**
```
  [*] Verifying email: john.doe@microsoft.com
  [+] Domain not in known disposable list

  [*] Checking MX records...
      MX Records:                 microsoft-com.mail.protection.outlook.com
  [+] Domain accepts email (MX records found)

  [*] Probing domain HTTP status...
      HTTP Status:                200
      Server:                     AkamaiGHost

      Is Disposable:              False
      Is Free Provider:           False
      Has Valid MX:               True
```

---

### Sub-option 2 — Email Header Analysis

**When to use:** A suspicious email was received. You've exported the raw headers from Outlook/Gmail and want to forensically examine them.

**How to get raw headers:**
- **Gmail:** Open email → three dots → "Show original"
- **Outlook:** File → Properties → Internet headers
- **Thunderbird:** View → Message Source

**Input:**
```
  Select: 2
  Paste raw email headers (end with a blank line):

Received: from mail.evil-server.ru (mail.evil-server.ru [45.142.212.100])
  by mx.targetcompany.com with ESMTP id abc123
  for <victim@targetcompany.com>; Wed, 25 Feb 2026 03:30:00 +0000
From: "IT Support" <support@micros0ft-help.com>
To: victim@targetcompany.com
Subject: Urgent: Your account will be suspended
Date: Wed, 25 Feb 2026 03:29:55 +0000
Reply-To: attacker@gmail.com
X-Mailer: PHPMailer 6.1.8
Authentication-Results: mx.targetcompany.com;
  spf=fail smtp.mailfrom=micros0ft-help.com;
  dkim=none;
  dmarc=fail

[blank line to submit]
```

**Expected Output:**
```
  ────────────────────────────────────────────────────────────
      From:           "IT Support" <support@micros0ft-help.com>
      To:             victim@targetcompany.com
      Subject:        Urgent: Your account will be suspended
      Date:           Wed, 25 Feb 2026 03:29:55 +0000
      Reply-To:       attacker@gmail.com

  [!] REPLY-TO MISMATCH - From and Reply-To differ (BEC indicator!)

  Authentication Results:
      SPF:            FAIL
      DKIM:           NOT FOUND
      DMARC:          FAIL

  [!] SPF FAILED - possible spoofing!
  [!] DMARC FAILED - possible spoofing!

  Received Hops (1 total):
    Hop 1: from mail.evil-server.ru (mail.evil-server.ru [45.142.212.100])...

  Public IPs found in headers: 45.142.212.100
  Run reputation check on these IPs? [y/N]: y

      Risk Score : 87/100  [CRITICAL]
      Abuse Score: 94
      ISP:         Media Land LLC (bulletproof hosting)

      X-Mailer:   PHPMailer 6.1.8
  ────────────────────────────────────────────────────────────
```

---

### Sub-option 3 — BEC (Business Email Compromise) Detector

**When to use:** A user forwarded a suspicious email body asking for an urgent wire transfer or gift card purchase. Scan it for BEC patterns.

**Input:**
```
  Select: 3
  Paste email body/subject to scan (end with blank line):

Hi Sarah,

I need you to process an urgent wire transfer of $45,000 to a new vendor account.
This is confidential - please do not discuss with anyone else.
Send the payment ASAP to account details below.
CEO - Robert Johnson

[blank line]
```

**Expected Output:**
```
  [*] Scanning for BEC (Business Email Compromise) patterns...
  [!] BEC INDICATORS FOUND (4):
       ⚠  'wire transfer'
       ⚠  'account details'
       ⚠  'urgent'
       ⚠  'confidential'

  [!] Urgency language detected: asap, urgent
```

---

### Sub-option 4 — Phishing Site Analysis

**When to use:** A user clicked a link and reported it as suspicious. You want to safely analyze the landing page without visiting it yourself.

**Input:**
```
  Select: 4
  Enter phishing site URL: http://micros0ft-login.xyz/secure/verify
```

**Expected Output:**
```
  [*] Analyzing phishing site: http://micros0ft-login.xyz/secure/verify

  [*] Submitting to URLScan.io...
      Scan UUID:      a1b2c3d4-e5f6-7890-abcd-ef1234567890
      Result URL:     https://urlscan.io/result/a1b2c3d4.../
      Screenshot:     https://urlscan.io/screenshots/a1b2c3d4...png

  [*] HTTP probe...
      HTTP Status:    200
      Server:         Apache/2.4.41

  [*] VirusTotal URL check...
      VT Malicious:   11
      VT Suspicious:  3
```

---

### Sub-option 5 — Phishing Identification Guidelines

**When to use:** Training new analysts or quickly reviewing phishing indicators during triage.

**Expected Output:**
```
  ╔══════════════════════════════════════════════════════════╗
  ║       PHISHING IDENTIFICATION GUIDELINES                 ║
  ╚══════════════════════════════════════════════════════════╝

  1. CHECK SENDER ADDRESS
     • Verify exact domain (not just display name)
     • Look for lookalike domains: paypa1.com vs paypal.com
     • Check Reply-To differs from From

  2. INSPECT LINKS BEFORE CLICKING
     • Hover over links - do they match display text?
     • Use URL decoders for SafeLink/shortened URLs
     • Look for IP addresses in URLs instead of domains

  3. EMAIL HEADER RED FLAGS
     • SPF / DKIM / DMARC FAIL
     • Multiple forwarding hops through suspicious countries
     • Timestamp anomalies in Received chain
  ...
```

---

## Option 4 — URL Decoding & Investigation

**Purpose:** Decode and investigate obfuscated, shortened, or security-wrapped URLs safely without clicking them.

---

### Sub-option 1 — Auto-Detect & Decode

**When to use:** You have a suspicious URL but don't know what type it is. Let SEAAT figure it out.

**Input:**
```
[SEAAT]> Select Option: 4
  Select: 1
  Enter URL to auto-detect & decode: https://nam02.safelinks.protection.outlook.com/?url=http%3A%2F%2Fevil.com%2Fpayload&data=...
```

**Expected Output:**
```
  [*] Auto-detecting URL type...
  [*] Decoding O365 SafeLink...
      Original SafeLink:  https://nam02.safelinks.protection.outlook.com/?url=http%3A...
      Decoded URL:        http://evil.com/payload
```

---

### Sub-option 2 — Standard URL Decode

**When to use:** URL contains percent-encoded characters like `%2F`, `%3A`, `%40`.

**Input:**
```
  Select: 2
  Enter URL-encoded string: http%3A%2F%2Fevil.com%2Flogin%3Fuser%3Dadmin%26pass%3D1234
```

**Expected Output:**
```
  [*] URL decoding...
      Original:   http%3A%2F%2Fevil.com%2Flogin%3Fuser%3Dadmin%26pass%3D1234
      Decoded:    http://evil.com/login?user=admin&pass=1234
```

---

### Sub-option 3 — Base64 Decode

**When to use:** A PowerShell command, email link, or phishing URL contains Base64 encoded data.

**Input:**
```
  Select: 3
  Enter Base64 string: aHR0cDovL21hbHdhcmUtYzIueHl6L2Rvd25sb2Fk
```

**Expected Output:**
```
  [*] Base64 decoding...
      Decoded:    http://malware-c2.xyz/download
```

---

### Sub-option 4 — O365 SafeLink Decoder

**When to use:** Microsoft 365 wraps all URLs in SafeLinks for protection. When investigating, you need the actual destination URL.

**Input:**
```
  Select: 4
  Enter SafeLink URL: https://eur01.safelinks.protection.outlook.com/?url=https%3A%2F%2Fphishing.site%2Fcredentials&data=04%7C01%7C...
```

**Expected Output:**
```
  [*] Decoding O365 SafeLink...
      Original SafeLink:  https://eur01.safelinks.protection.outlook.com/?url=...
      Decoded URL:        https://phishing.site/credentials
```

---

### Sub-option 5 — ProofPoint URL Defense Decoder

**When to use:** Organizations using ProofPoint email security will see URLs wrapped in `urldefense.proofpoint.com` format.

**Input:**
```
  Select: 5
  Enter ProofPoint URL: https://urldefense.proofpoint.com/v2/url?u=http-3A__malicious.site_payload&d=DwMFaQ&...
```

**Expected Output:**
```
  [*] Decoding ProofPoint URL Defense...
      Decoded URL:    http://malicious.site/payload
```

---

### Sub-option 7 — Unshorten URL

**When to use:** A phishing email contains a bit.ly or other shortened link. Expand it to see the real destination before anyone clicks.

**Input:**
```
  Select: 7
  Enter short URL: https://bit.ly/3xEvIlL
```

**Expected Output:**
```
  [*] Unshortening: https://bit.ly/3xEvIlL
      Final URL:    https://credential-harvester.ru/microsoft/login
      Status:       200
```

---

### Sub-option 8 — Full Redirect Chain Trace

**When to use:** A URL goes through multiple redirects before reaching its destination (common in phishing to evade scanners).

**Input:**
```
  Select: 8
  Enter URL to trace: http://tracking.spammer.com/click/abc123
```

**Expected Output:**
```
  [*] Tracing redirect chain for: http://tracking.spammer.com/click/abc123

  Redirect Chain (4 hop(s)):

     1. [301] http://tracking.spammer.com/click/abc123
     2. [302] https://redirect-service.io/go?id=XYZ
     3. [302] https://another-hop.net/landing
     4. [200] https://phishing-page.xyz/microsoft/signin

      Final Destination:  https://phishing-page.xyz/microsoft/signin
```

---

### Sub-option 9 — Extract IOCs from URL Structure

**When to use:** A complex URL may contain embedded IPs, domains, or parameters that are themselves IOCs.

**Input:**
```
  Select: 9
  Enter URL to extract from: https://malware-dropper.ru/stage2?callback=http%3A%2F%2F45.142.212.100%3A4444&token=aGVsbG8%3D
```

**Expected Output:**
```
  [*] Extracting IOCs from URL structure...
      Scheme:         https
      Domain:         malware-dropper.ru
      Path:           /stage2

  URL Parameters:
      callback = http://45.142.212.100:4444
      token    = aGVsbG8=

      Embedded IPs:   45.142.212.100
      Domains found:  malware-dropper.ru
```

---

## Option 5 — File Sandbox & Static Analysis

**Purpose:** Analyze suspicious files without executing them. Compute hashes, check threat databases, inspect PE headers, detect macros, and extract strings.

---

### Sub-option 1 — Analyze a File

**When to use:** A user received an email attachment (`invoice.docm`, `update.exe`) that your antivirus flagged or that looks suspicious.

**Input:**
```
[SEAAT]> Select Option: 5
  Select: 1
  Enter file path: /home/analyst/suspicious/invoice.exe
```

**Expected Output:**
```
  [*] Analyzing: invoice.exe

  ────────────────────────────────────────────────────────────
      File Name:                  invoice.exe
      File Size:                  284,672 bytes
      File Type:                  Windows PE/EXE
      MD5:                        44d88612fea8a8f36de82e1278abb02f
      SHA1:                       3395856ce81f2b7382dee72602f798b642f14d8b
      SHA256:                     275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f

  [*] Querying VirusTotal...
      VT Malicious:               48
      VT Suspicious:              2
      VT File Type:               Win32 EXE
      VT Tags:                    trojan, rat, upx, packed

  [*] Querying MalwareBazaar...
  [+] FOUND in MalwareBazaar!
      Signature:                  AgentTesla
      File Type:                  exe
      Tags:                       stealer, keylogger, rat
      First Seen:                 2026-01-15 09:23:41

  [*] Performing PE header analysis...
      Is EXE:                     True
      Is DLL:                     False
      Machine:                    0x14c (x86)
      Sections:                   .text, .rdata, .data, UPX0, UPX1
      DLL Imports:                KERNEL32.dll, ADVAPI32.dll, WS2_32.dll, WINHTTP.dll

  Extract readable strings? [y/N]: y

  [!] Suspicious strings (8):
      http://c2-server.ru/gate.php
      cmd.exe /c
      powershell -enc
      SOFTWARE\Microsoft\Windows\CurrentVersion\Run
      CreateRemoteThread
      VirtualAllocEx
      WScript.Shell
      keylog

  ────────────────────────────────────────────────────────────
```

---

**Expected Output for a macro-embedded Office file:**
```
  [*] Analyzing: invoice.docm
      File Type:                  Microsoft OLE (doc/xls/ppt)

  [*] Checking for VBA macros...
  [!] MACROS FOUND: 2 macro stream(s)
      Stream: VBA/ThisDocument
      Code snippet: Sub AutoOpen() Shell "powershell -enc JABj..."
```

---

### Sub-option 2 — Hash Lookup Only

**When to use:** You only have a hash (from an EDR alert, SIEM rule, or threat report) and want to check it without having the file.

**Input:**
```
  Select: 2
  Enter hash (MD5/SHA1/SHA256): 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
```

**Expected Output:**
```
      VT Malicious:   48
      VT Tags:        trojan, rat, upx
  [+] Found in MalwareBazaar!
      Signature:      AgentTesla
```

---

## Option 6 — IOC Sanitization

**Purpose:** Defang IOCs before pasting them into emails, tickets, or reports so they cannot be accidentally clicked. Also refang them back when needed for investigation.

---

### Sub-option 1 — Defang Single IOC

**When to use:** You need to share a malicious IP or URL in a Jira ticket, email, or report safely.

**Input:**
```
[SEAAT]> Select Option: 6
  Select: 1
  Enter IOC to defang: https://malware-c2.xyz/payload
```

**Expected Output:**
```
      Defanged:   hxxps[://]malware-c2[.]xyz/payload
```

**More examples:**
| Input | Defanged Output |
|-------|----------------|
| `185.220.101.45` | `185[.]220[.]101[.]45` |
| `attacker@evil.com` | `attacker[@]evil[.]com` |
| `http://bad.ru/mal` | `hxxp[://]bad[.]ru/mal` |

---

### Sub-option 2 — Refang Single IOC

**When to use:** You received a defanged IOC in a threat report and need to restore it for investigation.

**Input:**
```
  Select: 2
  Enter defanged IOC to restore: hxxps[://]malware-c2[.]xyz/payload
```

**Expected Output:**
```
      Refanged:   https://malware-c2.xyz/payload
```

---

### Sub-option 3 — Bulk Defang

**When to use:** An incident response report contains 20 IOCs. Defang all at once before emailing.

**Input:**
```
  Select: 3
  Paste text to defang (end with blank line):

185.220.101.45
https://malware-c2.xyz/payload
attacker@evil.com

[blank line]
```

**Expected Output:**
```
  ────────────────────────────────────────────────────────────
  185[.]220[.]101[.]45
  hxxps[://]malware-c2[.]xyz/payload
  attacker[@]evil[.]com
  ────────────────────────────────────────────────────────────

  Save to file? [y/N]: y
  Output file path: /home/analyst/defanged_iocs.txt
  [+] Saved to /home/analyst/defanged_iocs.txt
```

---

### Sub-option 5 — Process File

**When to use:** You have a full incident report text file with hundreds of IOCs to defang in bulk.

**Input:**
```
  Select: 5
  File path: /home/analyst/incident_report.txt
  Mode [defang/refang]: defang
```

**Expected Output:**
```
  [+] Output saved: /home/analyst/incident_report.txt.defanged.txt
```

---

## Option 7 — Brand Monitoring & Analysis

**Purpose:** Detect domain spoofing, phishing infrastructure clones, and lookalike domains targeting your organization's brand.

---

### Sub-option 1 — Typosquatting Detection

**When to use:** You want to find out if anyone has registered domains that look like your company's domain (for phishing or fraud).

**Input:**
```
[SEAAT]> Select Option: 7
  Select: 1
  Enter brand domain (e.g. example.com): aitr.ac.in
  Check DNS registration for each permutation? [y/N]: y
```

**Expected Output:**
```
  [*] Generating typosquatting permutations for: aitr.ac.in
  [*] Generated 87 permutations
  [*] Checking DNS registration (this may take a moment)...

  [!] REGISTERED TYPOSQUATS FOUND (2):
       ⚠  aitr.ac.com
       ⚠  aitrr.ac.in
```

**Without DNS check (just list permutations):**
```
  Sample permutations (first 30):
    aitr.ac.com
    aitr.ac.org
    aitr.ac.net
    aitrr.ac.in
    iatr.ac.in
    airt.ac.in
    myaitr.ac.in
    theaitr.ac.in
    aitr-login.ac.in
    aitr-secure.ac.in
    ...
```

---

### Sub-option 2 — Certificate Transparency Lookup

**When to use:** Find all subdomains and SSL certificates ever issued for a domain. This reveals phishing clones that obtained HTTPS certificates to appear legitimate.

**Input:**
```
  Select: 2
  Enter domain: targetbank.com
```

**Expected Output:**
```
  [*] Querying Certificate Transparency logs for: targetbank.com
      Unique Certificates Found:  142

  Recent entries (up to 20):
    2026-02-20  login.targetbank.com              Let's Encrypt
    2026-02-18  secure-login.targetbank.com       DigiCert
    2026-02-15  targetbank.com                    DigiCert
    2026-01-10  targetbank.com.verification-id.ru  Let's Encrypt   ← SUSPICIOUS
    2025-12-05  targetbank-login.support           Let's Encrypt   ← SUSPICIOUS
```

> **Red flag:** Certificates issued for domains like `targetbank.com.verification-id.ru` are clear phishing infrastructure.

---

### Sub-option 3 — Lookalike Domain Scoring

**When to use:** You found a suspicious domain and want to quantify how similar it is to your brand domain.

**Input:**
```
  Select: 3
  Enter legitimate brand domain: paypal.com
  Enter suspect domain: paypa1.com
```

**Expected Output:**
```
      Edit Distance:  1
      Similarity:     88.9%
      Verdict:        HIGH RISK
```

| Similarity | Verdict | Action |
|-----------|---------|--------|
| >80% | HIGH RISK | Likely impersonation, investigate |
| 60–80% | MEDIUM RISK | Monitor and assess |
| <60% | LOW RISK | Probably coincidental |

---

### Sub-option 4 — Geography / GeoIP of Domain

**When to use:** Quickly check where a suspicious domain or IP is hosted.

**Input:**
```
  Select: 4
  Enter URL or domain: malware-c2.xyz
```

**Expected Output:**
```
  [*] Geo check for: malware-c2.xyz
      Country:    RU
      Region:     Moscow
      City:       Moscow
      Org:        AS206728 Media Land LLC
      Hostname:   hosted-by.bulletproof-hoster.ru
```

---

## Option 8 — IOC Extractor

**Purpose:** Automatically extract all IOCs from raw text, email files, log files, or threat reports. Handles defanged IOCs automatically.

---

### Sub-option 1 — Extract from Pasted Text

**When to use:** You received a threat intelligence report or an email body and want to pull out all the IOCs instantly.

**Input:**
```
[SEAAT]> Select Option: 8
  Select: 1
  Paste text (end with a blank line):

Our honeypot detected connections from 185.220.101.45 and 45.142.212[.]100
targeting hxxps://malware-dropper[.]ru/stage2 and dropping payload with hash
44d88612fea8a8f36de82e1278abb02f. Contact attacker@protonmail.com reported
CVE-2021-44228 exploitation. Secondary C2 at evil-c2.xyz also observed.

[blank line]
```

**Expected Output:**
```
  [+] Extracted 7 IOC(s):

  ── IPv4 Addresses (2) ────────────────────────────────────
    • 185.220.101.45
    • 45.142.212.100          ← auto-refanged from [.]

  ── Domains (2) ───────────────────────────────────────────
    • malware-dropper.ru      ← auto-refanged from [.]
    • evil-c2.xyz

  ── URLs (1) ──────────────────────────────────────────────
    • https://malware-dropper.ru/stage2    ← auto-refanged from hxxps

  ── MD5 Hashes (1) ────────────────────────────────────────
    • 44d88612fea8a8f36de82e1278abb02f

  ── Email Addresses (1) ───────────────────────────────────
    • attacker@protonmail.com

  ── CVE IDs (1) ───────────────────────────────────────────
    • CVE-2021-44228

  Save IOCs to file? [y/N]: y
  Output path: /home/analyst/extracted_iocs.txt
  [+] IOCs saved to: /home/analyst/extracted_iocs.txt
```

---

### Sub-option 2 — Extract from File

**When to use:** Analyzing a `.eml` phishing email file, a firewall `.log` file, or a threat intelligence `.pdf` report.

**Input:**
```
  Select: 2
  File path: /home/analyst/phishing_email.eml
```

**Expected Output:**
```
  [*] Reading: /home/analyst/phishing_email.eml
  [*] Read 4,821 characters

  [+] Extracted 12 IOC(s):

  ── IPv4 Addresses (3) ──────────────────────────────────
    • 45.142.212.100
    • 192.168.1.50             ← filtered as private? No - shown
    • 198.51.100.1

  ── Domains (4) ─────────────────────────────────────────
    • micros0ft-help.com
    • evil-redirect.net
    • phishing-page.xyz
    • malware-c2.ru

  ── URLs (2) ────────────────────────────────────────────
    • https://phishing-page.xyz/microsoft/signin
    • http://malware-c2.ru/download/payload.exe

  ── Email Addresses (3) ─────────────────────────────────
    • attacker@gmail.com
    • noreply@micros0ft-help.com
    • victim@targetcompany.com
```

---

### Sub-option 3 — Extract and Run Reputation Checks

**When to use:** Maximum automation. Extract all IOCs from a file and immediately check them all.

**Input:**
```
  Select: 3
  File path: /home/analyst/alert_data.txt

  Which IOC types to check reputation on?
    [ipv4] 3 items
    [domain] 4 items
    [url] 2 items
  Enter types (comma separated, e.g. ipv4,domain,url): ipv4,domain
```

**Expected Output:**
```
  [*] Checking ipv4 IOCs...
      IOC: 185.220.101.45   Risk Score: 87/100 [CRITICAL]
      IOC: 45.142.212.100   Risk Score: 72/100 [HIGH]
      IOC: 198.51.100.1     Risk Score: 5/100  [CLEAN]

  [*] Checking domain IOCs...
      IOC: malware-c2.ru    Risk Score: 68/100 [HIGH]
      IOC: evil-redirect.net Risk Score: 55/100 [HIGH]
      ...
```

---

## Option 9 — Threat Intelligence Correlation

**Purpose:** Correlate IOCs with known threat campaigns, MITRE ATT&CK techniques, and threat actor groups.

---

### Sub-option 1 — ThreatFox IOC Lookup (Free)

**When to use:** Check if an IOC is associated with known malware families in the abuse.ch ThreatFox database. No API key required.

**Input:**
```
[SEAAT]> Select Option: 9
  Select: 1
  Enter IOC: 185.220.101.45
  IOC type [ip/domain/url/hash]: ip
```

**Expected Output:**
```
  [*] Querying ThreatFox for: 185.220.101.45
      ThreatFox Results:  2

      ID:          1234567
      IOC:         185.220.101.45:4444
      Threat Type: botnet_cc
      Malware:     Cobalt Strike
      Confidence:  75%
      First Seen:  2026-01-10 14:32:00

      ID:          1234568
      IOC:         185.220.101.45:8080
      Threat Type: botnet_cc
      Malware:     Metasploit
      Confidence:  60%
      First Seen:  2025-12-05 09:11:00
```

---

### Sub-option 2 — AlienVault OTX Pulse Search

**When to use:** Search for threat intelligence pulses related to a malware family, threat actor, or campaign name.

**Input:**
```
  Select: 2
  Search query (threat actor / malware name / IOC): Lazarus Group
```

**Expected Output:**
```
  [*] Searching OTX pulses for: Lazarus Group
      Pulses Found:  5

      Name:     Lazarus Group North Korea APT Campaign 2026
      Author:   alienvault
      Tags:     apt, north-korea, lazarus, backdoor
      TLP:      white
      Modified: 2026-02-20

      Name:     DPRK Financial Sector Attacks - IOC List
      Author:   US-CERT
      Tags:     financial, dprk, lazarus
      TLP:      white
      Modified: 2026-01-15
      ...
```

---

### Sub-option 3 — MITRE ATT&CK Technique Lookup

**When to use:** During an investigation you identify a behavior (e.g., PowerShell execution, credential dumping). Look up the ATT&CK technique to understand it and document the TTP.

**Input by technique ID:**
```
  Select: 3
  Enter technique ID (T1566) or keyword (phishing): T1566
```

**Expected Output:**
```
      Technique ID:   T1566
      Name:           Phishing
      Reference:      https://attack.mitre.org/techniques/T1566/
      Tactic:         TA0001 - Initial Access
```

**Input by keyword:**
```
  Enter technique ID or keyword: credential dump
```

**Expected Output:**
```
  [*] Found 1 matching techniques:
      T1003: OS Credential Dumping
```

---

### Sub-option 4 — MITRE ATT&CK Tactics Overview

**When to use:** Quick reference during incident documentation or threat hunting planning.

**Expected Output:**
```
  MITRE ATT&CK Tactics Overview

  TA0001  Initial Access             T1566(Phishing), T1078(Valid Accounts), T1190(Exploit Public-Facing App)
  TA0002  Execution                  T1059(Scripting Interpreter), T1203(Client Execution)
  TA0003  Persistence                T1547(Autostart Execution), T1053(Scheduled Task)
  TA0004  Privilege Escalation       T1548(Abuse Elevation Control), T1134(Token Manipulation)
  TA0005  Defense Evasion            T1055(Process Injection), T1027(Obfuscation)
  TA0006  Credential Access          T1110(Brute Force), T1003(Credential Dumping)
  TA0007  Discovery                  T1087(Account Discovery), T1083(File Discovery)
  TA0008  Lateral Movement           T1021(Remote Services), T1550(Alternate Auth)
  TA0009  Collection                 T1005(Local Data), T1114(Email Collection)
  TA0010  Exfiltration               T1048(Alt Protocol), T1041(C2 Channel)
  TA0011  Command & Control          T1071(App Layer Protocol), T1090(Proxy)
  TA0040  Impact                     T1486(Ransomware), T1489(Service Stop)
```

---

### Sub-option 5 — IOC Age / Decay Score

**When to use:** You found an IOC from an old threat report. Calculate how relevant it still is today.

**Input:**
```
  Select: 5
  Enter IOC: 185.220.101.45
  First seen date (YYYY-MM-DD): 2025-06-15
```

**Expected Output:**
```
      Age (days):         255
      Relevance Score:    40/100
      Label:              AGING
```

> **IOC Decay Guide:**
> | Age | Score | Label |
> |-----|-------|-------|
> | ≤7 days | 100 | VERY FRESH |
> | ≤30 days | 80 | FRESH |
> | ≤90 days | 60 | RECENT |
> | ≤180 days | 40 | AGING |
> | ≤365 days | 20 | STALE |
> | 1+ year | 5 | EXPIRED |

---

## Option 10 — Network Analysis & Pivot

**Purpose:** Deep-dive into network infrastructure. Find what services are exposed, how an IP is classified, and what other assets share the same infrastructure.

---

### Sub-option 1 — Shodan Host Lookup

**When to use:** Understand what services a suspicious IP is running, what CVEs it's exposed to, and what ports are open.

**Input:**
```
[SEAAT]> Select Option: 10
  Select: 1
  Enter IP address: 45.142.212.100
```

**Expected Output (with API key):**
```
  [*] Shodan lookup for: 45.142.212.100
      Organization:               Media Land LLC
      ISP:                        Frantech Solutions
      Country:                    Russia
      OS:                         Ubuntu 20.04
      Open Ports:                 22, 80, 443, 4444, 8080
      Hostnames:                  None
      Domains:                    malware-c2.xyz, evil-dropper.ru

  [!] Known CVEs (3): CVE-2021-44228, CVE-2022-0778, CVE-2023-23397
```

**Expected Output (without API key — uses free Shodan InternetDB):**
```
      Open Ports:     22, 80, 443, 4444, 8080
      CPEs:           cpe:/a:apache:http_server:2.4.41
      Tags:           self-signed, eol-product
      Vulns:          CVE-2021-44228, CVE-2022-0778

  [!] Known vulnerabilities: CVE-2021-44228, CVE-2022-0778
```

---

### Sub-option 2 — GreyNoise IP Check

**When to use:** Determine if an IP in your logs is mass-scanning the internet (internet noise / background radiation) or specifically targeting your organization.

**Input:**
```
  Select: 2
  Enter IP address: 198.51.100.50
```

**Expected Output (internet noise):**
```
  [*] Checking GreyNoise for: 198.51.100.50
      IP:             198.51.100.50
      Noise:          True
      Riot:           False
      Classification: malicious
      Name:           Mirai
      Last Seen:      2026-02-24

  [!] IP is INTERNET NOISE - seen mass-scanning the internet
```

**Expected Output (known benign service):**
```
      Noise:          False
      Riot:           True
      Classification: benign
      Name:           Google Bot

  [+] IP is a known benign service (RIOT)
```

> **Key distinction:** A NOISE IP hitting your firewall is background radiation (low priority). An IP that is NOT noise targeting you specifically is a high-priority investigation.

---

### Sub-option 3 — ASN / BGP Lookup

**When to use:** Understand what autonomous system an IP belongs to and whether it's associated with bulletproof hosting providers known to ignore abuse complaints.

**Input:**
```
  Select: 3
  Enter IP or AS number: 45.142.212.100
```

**Expected Output:**
```
  [*] ASN lookup: 45.142.212.100
      ASN:            206728
      AS Name:        Media Land LLC
      Country:        RU
      First IP:       45.142.212.0
      Last IP:        45.142.212.255

  [!] AS206728 is associated with bulletproof hosting!
```

---

### Sub-option 4 — Reverse IP Pivot

**When to use:** You found one malicious domain. Pivot to find ALL other domains hosted on the same IP — threat actors often run multiple malicious domains on shared infrastructure.

**Input:**
```
  Select: 4
  Enter IP address: 45.142.212.100
```

**Expected Output:**
```
  [*] Reverse IP pivot for: 45.142.212.100
      Domains on same IP: 8

    • malware-c2.xyz
    • phishing-paypal.ru
    • evil-dropper.net
    • credential-harvest.xyz
    • fake-microsoft-login.com
    • ransomware-distribution.ru
    • botnet-panel.xyz
    • c2-command-control.net
```

> **Value:** One confirmed malicious IP can reveal an entire threat actor's infrastructure in seconds.

---

### Sub-option 5 — C2 Beacon Detector

**When to use:** You have network connection logs and suspect a workstation is infected with malware that regularly calls back to a C2 server. Beaconing = regular timed connections = malware.

**Prepare log format:**
```
2026-02-25T01:00:00 185.220.101.45 443
2026-02-25T01:05:01 185.220.101.45 443
2026-02-25T01:10:00 185.220.101.45 443
2026-02-25T01:14:59 185.220.101.45 443
2026-02-25T01:20:00 185.220.101.45 443
2026-02-25T02:00:00 8.8.8.8 53
2026-02-25T03:45:22 8.8.8.8 53
```

**Input:**
```
  Select: 5
  Paste connection log (end with blank line):
[paste log above]
[blank line]
```

**Expected Output:**
```
  [*] Analyzing for C2 beaconing patterns...
      Unique Destinations:    2

  [!] POTENTIAL C2 BEACONS DETECTED (1):

      IP: 185.220.101.45
      Connections: 5
      Mean Interval: 300.2s
      Jitter: 0.1%
```

> **How it works:** Legitimate user traffic is irregular. Malware beacons at near-perfect intervals (low jitter). Jitter below 10% with 5+ connections is a strong C2 indicator.

---

## Option 11 — Case Manager

**Purpose:** SOC-style investigation tracking. Document every IOC, verdict, and note in a structured case that can be exported, shared, and used for shift handovers.

---

### Sub-option 1 — List All Cases

**Input:**
```
[SEAAT]> Select Option: 11
  Select: 1
```

**Expected Output:**
```
  ID                        Title                               Status          IOCs
  ─────────────────────────────────────────────────────────────────────────────────
  CASE-20260225-034512      Phishing Campaign - Finance Dept    OPEN            12
  CASE-20260224-091233      Ransomware Alert - Workstation 7    OPEN            8
  CASE-20260223-153001      BEC Attempt - CEO Impersonation     CLOSED          5
```

---

### Sub-option 2 — Create New Case

**Input:**
```
  Select: 2
  Case title: Phishing Campaign - Finance Dept
  Analyst name: Alfiya Khanam
  Severity [LOW/MEDIUM/HIGH/CRITICAL]: HIGH
  Brief description: Multiple employees received phishing emails impersonating Microsoft 365 login page

  [+] Case created: CASE-20260225-034512
```

---

### Sub-option 3 — View Case

**Input:**
```
  Select: 3
  Case ID: CASE-20260225-034512
```

**Expected Output:**
```
  ══════════════════════════════════════════════════════════════
  CASE: CASE-20260225-034512
  ──────────────────────────────────────────────────────────────
      Title:          Phishing Campaign - Finance Dept
      Analyst:        Alfiya Khanam
      Severity:       HIGH
      Status:         OPEN
      Created:        2026-02-25T03:45:12
      Description:    Multiple employees received phishing emails impersonating Microsoft 365

  IOCs (4):
    [MALICIOUS            ] domain   micros0ft-login.xyz
    [MALICIOUS            ] ip       45.142.212.100
    [SUSPICIOUS           ] url      https://micros0ft-login.xyz/signin
    [FALSE_POSITIVE       ] ip       192.168.1.1

  Notes (2):
    [2026-02-25T04:12:00] URL submitted to URLScan - screenshot confirms Microsoft clone page
    [2026-02-25T04:45:00] 3 users confirmed they clicked the link - IT notified for remediation

  ══════════════════════════════════════════════════════════════
```

---

### Sub-option 4 — Add IOC to Case

**Input:**
```
  Select: 4
  Case ID: CASE-20260225-034512
  IOC value: 45.142.212.100
  IOC type [ip/domain/url/hash/email]: ip
  Verdict [malicious/suspicious/false_positive/under_investigation]: malicious
  Tags (comma separated): c2, phishing-infrastructure, bulletproof-hosting

  [+] IOC added to CASE-20260225-034512
```

---

### Sub-option 6 — Export Case

**Input:**
```
  Select: 6
  Case ID: CASE-20260225-034512
  Export format [json/markdown]: markdown
  Output file path: /home/analyst/reports/case-report.md
```

**Expected Markdown Output:**
```markdown
# SEAAT Case Report: CASE-20260225-034512

**Title:** Phishing Campaign - Finance Dept
**Analyst:** Alfiya Khanam
**Severity:** HIGH
**Status:** OPEN
**Created:** 2026-02-25T03:45:12

## Description
Multiple employees received phishing emails impersonating Microsoft 365

## IOCs (4)

| IOC | Type | Verdict | Tags |
|-----|------|---------|------|
| micros0ft-login.xyz | domain | malicious | phishing, clone |
| 45.142.212.100 | ip | malicious | c2, bulletproof-hosting |
...

## Analyst Notes

- `2026-02-25T04:12:00` URL submitted to URLScan - screenshot confirms Microsoft clone
- `2026-02-25T04:45:00` 3 users confirmed they clicked - IT notified

---
*Generated by SEAAT v2.0*
```

---

### Sub-option 7 — Shift Handover Report

**When to use:** End of shift. Auto-generate a handover document summarizing all open cases for the incoming analyst.

**Input:**
```
  Select: 7
```

**Expected Output:**
```
  [+] Handover report saved: /reports/cases/handover_20260225_0600.md

# SEAAT Shift Handover Report
**Generated:** 2026-02-25 06:00
**Open Cases:** 2

## Open Cases Summary

### CASE-20260225-034512 - Phishing Campaign - Finance Dept
- **Severity:** HIGH
- **Analyst:** Alfiya Khanam
- **IOCs:** 4
- **Description:** Multiple employees received phishing emails...

### CASE-20260224-091233 - Ransomware Alert - Workstation 7
- **Severity:** CRITICAL
- **Analyst:** Riya Dubey
- **IOCs:** 8
- **Description:** Endpoint Detection triggered on workstation WS-007...
```

---

## Option 12 — SIEM / SOAR Toolbox

**Purpose:** Generate detection queries, Sigma rules, firewall block rules, and run structured investigation playbooks.

---

### Sub-option 1 — SIEM Hunt Query Generator

**When to use:** You identified a malicious IOC and now need to search your entire environment's logs to find any hosts that communicated with it.

**Input:**
```
[SEAAT]> Select Option: 12
  Select: 1
  Enter IOC: 185.220.101.45
  IOC type [ip/domain/url/hash/email]: ip
```

**Expected Output:**
```
  [*] Generating SIEM hunt queries for ip: 185.220.101.45

  ── SPLUNK ──────────────────────────────────────────────────
    index=* (src_ip="185.220.101.45" OR dest_ip="185.220.101.45"
             OR src="185.220.101.45" OR dest="185.220.101.45")

  ── ELASTIC ─────────────────────────────────────────────────
    (source.ip: "185.220.101.45" OR destination.ip: "185.220.101.45"
     OR network.destination.ip: "185.220.101.45")

  ── SENTINEL ────────────────────────────────────────────────
    union isfuzzy=true DeviceNetworkEvents, CommonSecurityLog
    | where RemoteIP == "185.220.101.45" or DestinationIP == "185.220.101.45"

  ── QRADAR ──────────────────────────────────────────────────
    SELECT * FROM events WHERE sourceip = '185.220.101.45'
    OR destinationip = '185.220.101.45' LAST 7 DAYS
```

---

### Sub-option 2 — Sigma Rule Generator

**When to use:** You want to create a permanent, vendor-neutral detection rule that can be deployed to your SIEM to catch this IOC in future.

**Input:**
```
  Select: 2
  Enter IOC: malware-c2.xyz
  IOC type [ip/domain/url/hash/email]: domain
  Rule title (leave blank for auto): Malware C2 Domain Communication
  Description (leave blank for auto): Detects outbound DNS query to known malware C2 domain
```

**Expected Output:**
```yaml
title: Malware C2 Domain Communication
id: seaat-20260225034512
status: experimental
description: Detects outbound DNS query to known malware C2 domain
author: SEAAT Auto-Generator
date: 2026/02/25
tags:
    - attack.threat_intel
logsource:
    category: network
    product: zeek
detection:
    detection:
        dns.query.name: 'malware-c2.xyz'
        url.domain: 'malware-c2.xyz'
  condition: detection
fields:
    - src_ip
    - dst_ip
    - url
    - dns.query.name
falsepositives:
    - Review context before blocking
level: high

  Save Sigma rule to file? [y/N]: y
  Output path (.yml): /home/analyst/rules/malware-c2-domain.yml
  [+] Sigma rule saved: /home/analyst/rules/malware-c2-domain.yml
```

---

### Sub-option 3 — Firewall Block Rule Generator

**When to use:** Investigation confirmed an IP is malicious. Generate ready-to-deploy block rules for your firewall platform.

**Input:**
```
  Select: 3
  Enter IOC(s) comma-separated: 185.220.101.45, 45.142.212.100
  IOC type [ip/domain]: ip
```

**Expected Output:**
```
  Firewall Block Rules for 2 ip(s):

  ── iptables (Linux)
    iptables -A INPUT  -s 185.220.101.45 -j DROP
    iptables -A OUTPUT -d 185.220.101.45 -j DROP
    iptables -A INPUT  -s 45.142.212.100 -j DROP
    iptables -A OUTPUT -d 45.142.212.100 -j DROP

  ── Windows Defender Firewall (PowerShell)
    New-NetFirewallRule -DisplayName "SEAAT-Block-185.220.101.45" -Direction Inbound -RemoteAddress 185.220.101.45 -Action Block
    New-NetFirewallRule -DisplayName "SEAAT-Block-45.142.212.100" -Direction Inbound -RemoteAddress 45.142.212.100 -Action Block

  ── Cisco ASA
    access-list SEAAT-BLOCK deny ip 185.220.101.45 255.255.255.255 any
    access-list SEAAT-BLOCK deny ip 45.142.212.100 255.255.255.255 any

  ── pfSense / OPNsense (pfctl)
    pfctl -t seaat_blacklist -T add 185.220.101.45
    pfctl -t seaat_blacklist -T add 45.142.212.100
```

---

### Sub-option 4 — Run Investigation Playbook

**When to use:** You receive a new alert type and want a structured, step-by-step workflow to follow. Playbooks ensure no investigation step is missed.

**Input:**
```
  Select: 4
  Available playbooks:
    [phishing_email]    Phishing Email Triage
    [malicious_ip]      Malicious IP Investigation
    [ransomware_hash]   Ransomware File Analysis

  Enter playbook name: phishing_email
```

**Expected Output:**
```
  [*] Starting playbook: Phishing Email Triage

  Steps to complete:

   1. Extract IOCs from email
   2. Analyze email headers
   3. Check sender reputation
   4. Check URLs in body
   5. Check attachments
   6. Tag IOCs and create/update case

  Use SEAAT menu options to execute each step.
  Recommended workflow: complete each step in order and
  document findings in Case Manager.
```

---

### Sub-option 5 — Show Available Playbooks

**Expected Output:**
```
  [phishing_email] Phishing Email Triage
    1. Extract IOCs from email
    2. Analyze email headers
    3. Check sender reputation
    4. Check URLs in body
    5. Check attachments
    6. Tag IOCs and create/update case

  [malicious_ip] Malicious IP Investigation
    1. Check IP reputation (VT + AbuseIPDB + OTX)
    2. Shodan host lookup
    3. GreyNoise check
    4. ASN / ISP lookup
    5. Reverse IP pivot
    6. Generate SIEM hunt queries
    7. Generate firewall block rules
    8. Create case record

  [ransomware_hash] Ransomware File Analysis
    1. Compute file hashes
    2. VirusTotal file check
    3. MalwareBazaar lookup
    4. Static analysis (PE/strings)
    5. ThreatFox IOC lookup
    6. Check for C2 indicators
    7. Generate Sigma rule
    8. Create case + tag as CRITICAL
```

---

## Option C — Help & Configuration

**Purpose:** Configure API keys, view the audit log, clear the cache, and read the help reference.

---

### Sub-option 1 — Help & About

**Input:**
```
[SEAAT]> Select Option: C
  Select: 1
```

**Expected Output:**
```
  ╔══════════════════════════════════════════════════════════╗
  ║                    SEAAT v2.0 HELP                       ║
  ╠══════════════════════════════════════════════════════════╣
  ║                                                          ║
  ║  SEAAT (Security Event Analysis Automation Tool)         ║
  ║  is a unified CLI platform for SOC analysts to:          ║
  ║                                                          ║
  ║  • Validate IOCs (IPs, domains, URLs, hashes)            ║
  ║  • Analyze phishing emails and headers                   ║
  ║  ...                                                     ║
  ║  REQUIRED APIs:                                          ║
  ║    VirusTotal, AbuseIPDB, AlienVault OTX                 ║
  ║                                                          ║
  ║  OPTIONAL APIs:                                          ║
  ║    URLScan, APIVoid, Shodan, GreyNoise                   ║
  ╚══════════════════════════════════════════════════════════╝
```

---

### Sub-option 2 — Configure API Keys

**When to use:** First run, or when adding/rotating API keys.

**Input:**
```
  Select: 2
```

**Expected Output:**
```
  ╔════════════════════════════════════════════════════════════╗
  ║              API KEY CONFIGURATION                         ║
  ╚════════════════════════════════════════════════════════════╝

  [*] Enter API keys (press Enter to skip optional keys)
  Leave blank to keep existing value.

  VirusTotal (https://www.virustotal.com/gui/my-apikey)
  Current: [********************abcd]  New value: ___

  AbuseIPDB (https://www.abuseipdb.com/account/api)
  Current: [not set]  New value: your_key_here

  AlienVault OTX (https://otx.alienvault.com/api)
  Current: [not set]  New value: ___

  URLScan.io (https://urlscan.io/user/profile/)
  Current: [not set]  New value: ___

  APIVoid (https://www.apivoid.com/api/)
  Current: [not set]  New value: ___

  Shodan (https://account.shodan.io/) [optional]
  Current: [not set]  New value: ___

  Use encryption for API keys? [Y/n]: Y
  [+] API keys encrypted and saved.
  [+] Configuration saved!
```

---

### Sub-option 3 — View Audit Log

**When to use:** Reviewing what actions were taken during an investigation session for compliance, chain of custody, or debugging.

**Input:**
```
  Select: 3
```

**Expected Output:**
```
  Last 20 audit entries:

  2026-02-25T03:45:12  [CONFIG_SAVE]      API keys updated
  2026-02-25T03:46:01  [REPUTATION_CHECK] ip:185.220.101.45
  2026-02-25T03:47:33  [WHOIS_LOOKUP]     malware-c2.xyz
  2026-02-25T03:48:10  [EMAIL_VERIFY]     hiyito7664@kaoing.com
  2026-02-25T03:49:55  [HEADER_ANALYSIS]  raw headers parsed
  2026-02-25T03:51:02  [BEC_DETECT]       hits=4
  2026-02-25T03:52:44  [SAFELINK_DECODE]  https://phishing-page.xyz/...
  2026-02-25T03:53:18  [FILE_ANALYSIS]    invoice.exe sha256=275a021b...
  2026-02-25T03:55:01  [CASE_CREATE]      CASE-20260225-034512
  2026-02-25T03:56:30  [CASE_ADD_IOC]     CASE-20260225-034512:185.220.101.45
  2026-02-25T03:57:12  [SIEM_QUERY]       ip:185.220.101.45
  2026-02-25T03:58:00  [SIGMA_RULE]       domain:malware-c2.xyz
```

---

### Sub-option 4 — Clear Cache

**When to use:** API responses are cached for 1 hour to avoid rate-limits. Clear the cache to force fresh results.

**Input:**
```
  Select: 4
```

**Expected Output:**
```
  [+] Cache cleared.
```

---

## 🔄 Full Investigation Workflow Example

**Scenario:** A user reports clicking a suspicious link in an email.

```
Step 1  → [C] Configure API keys (first time only)

Step 2  → [3] Email Security
              Sub-option 2: Paste raw email headers
              → Identifies: SPF FAIL, Reply-To mismatch, sender IP 45.142.212.100

Step 3  → [1] Reputation Check
              Enter: 45.142.212.100
              → Risk Score: 87/100 CRITICAL, AbuseIPDB: 94, OTX: 23 pulses

Step 4  → [4] URL Decoding
              Sub-option 8: Redirect chain trace on the link
              → Final destination: https://phishing-page.xyz/microsoft/signin

Step 5  → [8] IOC Extractor
              Sub-option 2: Extract from the .eml file
              → Finds: 3 IPs, 2 domains, 1 URL

Step 6  → [7] Brand Monitoring
              Sub-option 3: Lookalike score - microsoft.com vs micros0ft-login.xyz
              → Similarity: 84% HIGH RISK

Step 7  → [10] Network Analysis
              Sub-option 4: Reverse IP pivot on 45.142.212.100
              → 8 other malicious domains on same server

Step 8  → [9] Threat Intelligence
              Sub-option 1: ThreatFox lookup
              → Associated with Cobalt Strike C2

Step 9  → [11] Case Manager
              Create case: "Phishing Campaign - Finance Dept" CRITICAL
              Add all IOCs with verdict MALICIOUS

Step 10 → [12] SIEM / SOAR Toolbox
              Generate hunt queries for Splunk
              Generate firewall rules for 45.142.212.100
              Generate Sigma rule for malicious domain
              Export case as Markdown report
```

---

*SEAAT v2.0 — Security Event Analysis & Automation Tool*
*Dept. of CSE - Cyber Security | AITR, Indore | 2022–2026*
