# 🛡️ SEAAT — Security Event Analysis Automation Tool
### v2.0 | CSE - Cyber Security | AITR, Indore | 2022–2026

> **SOC Analyst's Unified Threat Investigation Platform**  
> A free, open, modular Python CLI tool for automating Indicators of Compromise (IOC) analysis, phishing investigations, threat intelligence correlation, and SOAR workflows.

---

## 📋 Overview

SEAAT centralizes all essential SOC investigation tasks into one unified, automated, menu-driven tool. It replaces the time-consuming manual workflow of switching between VirusTotal, AbuseIPDB, OTX, URLScan, and dozens of other platforms.

**Developed by:**  
Alfiya Khanam · Riya Dubey · Rudra Potghan  
*Dept. of Computer Science & Engineering - Cyber Security, AITR Indore*

---

## 🏗️ Project Structure

```
SEAAT/
├── main.py                  # Entry point + ASCII banner
├── setup.py                 # One-time setup & dependency installer
├── requirements.txt         # Python dependencies
│
├── core/                    # Core framework
│   ├── banner.py            # ASCII banner, menus, color output
│   ├── router.py            # Menu dispatcher
│   ├── config_manager.py    # Encrypted API key management
│   ├── api_helper.py        # HTTP wrapper with caching
│   └── audit_log.py         # Tamper-evident audit logging
│
├── modules/                 # Feature modules (one per menu item)
│   ├── reputation_check.py  # [1] IOC reputation (VT, AbuseIPDB, OTX, APIVoid)
│   ├── dns_module.py        # [2] DNS, WHOIS, SPF/DKIM/DMARC, fast-flux
│   ├── phishing_analysis.py # [3] Email verify, headers, BEC, phishing sites
│   ├── url_decoding.py      # [4] URL decode, SafeLink, ProofPoint, chains
│   ├── file_sandbox.py      # [5] Hashes, VT, MalwareBazaar, PE, macros
│   ├── sanitize.py          # [6] Defang / refang IOCs
│   ├── brand_monitor.py     # [7] Typosquat, crt.sh, lookalike scoring
│   ├── ioc_extractor.py     # [8] Extract IOCs from text/files
│   ├── threat_intel.py      # [9] ThreatFox, OTX pulses, MITRE ATT&CK
│   ├── network_analysis.py  # [10] Shodan, GreyNoise, ASN, pivot, C2 detection
│   ├── case_manager.py      # [11] Investigation case tracking & reports
│   ├── soar_toolbox.py      # [12] Sigma rules, SIEM queries, firewall rules
│   └── config_module.py     # [C] API config, audit log, help
│
├── config/                  # Encrypted API key storage (git-ignored)
│   ├── seaat.key            # Fernet encryption key
│   └── seaat_config.enc     # Encrypted API keys
│
├── data/
│   ├── cache/               # SQLite/JSON API response cache
│   └── disposable_domains.txt  # Cached temp email domain list
│
├── reports/
│   ├── audit.log            # Tamper-evident session audit log
│   └── cases/               # Investigation case JSON files
│
└── plugins/                 # Drop custom lookup modules here
```

---

## 🚀 Quick Start

```bash
# 1. Clone or extract
cd SEAAT/

# 2. Run setup (installs dependencies, creates directories)
python setup.py

# 3. Launch
python main.py
```

---

## 📦 Dependencies

### Core (Required)
| Package | Purpose |
|---------|---------|
| `requests` | HTTP API calls |
| `cryptography` | API key encryption (Fernet) |
| `dnspython` | DNS record lookups |
| `python-whois` | WHOIS domain intelligence |
| `colorama` | Colored terminal output |

### Optional (Enhanced Functionality)
| Package | Feature |
|---------|---------|
| `pefile` | PE header analysis for executables |
| `oletools` | VBA macro detection in Office files |
| `pdfminer.six` | PDF text and URL extraction |
| `yara-python` | YARA pattern scanning |

```bash
pip install -r requirements.txt
# Optional:
pip install pefile oletools pdfminer.six
```

---

## 🔑 API Keys

Configure on first run or via Menu → `[C] Help & Configuration`

| API | Key Required | Free Tier | Used For |
|-----|-------------|-----------|---------|
| VirusTotal | ✅ Yes | ✅ Yes | IOC reputation, file hash lookup |
| AbuseIPDB | ✅ Yes | ✅ Yes | IP abuse score |
| AlienVault OTX | ✅ Yes | ✅ Yes | Threat pulses, IOC intel |
| URLScan.io | ✅ Yes | ✅ Yes | Website scanning |
| APIVoid | ✅ Yes | ✅ Limited | Email verify, domain blacklists |
| Shodan | ⚡ Optional | Limited | Port/service fingerprinting |
| GreyNoise | ⚡ Optional | ✅ Community | Internet noise classification |

**All API keys are encrypted at rest using Fernet symmetric encryption.**

---

## 🧩 Feature Modules

### 1. Reputation / Blocklist Check
- IP, Domain, URL, and Hash reputation via VirusTotal, AbuseIPDB, OTX, APIVoid
- Normalized 0–100 risk score with CLEAN/LOW/MEDIUM/HIGH/CRITICAL verdict
- Bulk IOC checking from file

### 2. DNS / WHOIS Lookup
- A, MX, NS, TXT, CNAME record lookup
- Reverse DNS, WHOIS with domain age calculation
- SPF, DKIM, DMARC email authentication record check
- Fast-flux detection (low TTL + many A records)
- ISP/GeoIP lookup via ipinfo.io

### 3. Email Security & Phishing Analysis
- Email address verification with APIVoid
- Temp/disposable email detection (DNS probe + 100k domain list)
- Domain HTTP probing to confirm if site exists
- Email header parsing: SPF/DKIM/DMARC results, hop analysis, IP extraction
- BEC keyword scanner (wire transfer, urgency language, gift cards)
- Phishing site analysis via URLScan.io + VirusTotal

### 4. URL Decoding & Investigation
- Auto-detect URL type and decode
- O365 SafeLink decoder
- ProofPoint URL Defense decoder
- Mimecast URL Protect decoder
- Base64 / URL percent-encoding decoder
- URL shortener expander (bit.ly, t.co, etc.)
- Full redirect chain tracer
- IOC extraction from URL structure

### 5. File Sandbox & Static Analysis
- SHA256/SHA1/MD5 hash computation
- Magic byte file type detection
- VirusTotal hash lookup
- MalwareBazaar lookup (free, no key)
- PE header analysis (imports, sections, DLL/EXE flags)
- VBA macro detection (oletools)
- PDF JavaScript/URI extraction
- Suspicious string extraction from binaries

### 6. IOC Sanitization
- Defang IOCs for safe sharing (hxxps://, [.], [@])
- Refang defanged IOCs back to usable form
- Bulk text processing
- File input/output support

### 7. Brand Monitoring & Analysis
- Typosquatting permutation generator (deletion, transposition, substitution, TLD swap)
- DNS registration check for typosquats
- Certificate Transparency lookup via crt.sh
- Lookalike domain scoring (Levenshtein distance + similarity %)
- Domain GeoIP check

### 8. IOC Extractor
- Auto-extract from pasted text, .eml, .log, .txt, .csv, .pdf
- Handles defanged/obfuscated IOCs (auto-refangs)
- Detects: IPv4, IPv6, domains, URLs, MD5, SHA1, SHA256, emails, CVEs
- Save results to file
- Option to immediately run reputation checks on extracted IOCs

### 9. Threat Intelligence Correlation
- ThreatFox IOC lookup (free, no API key required)
- AlienVault OTX pulse search
- Compact MITRE ATT&CK tactics/techniques reference
- IOC age/decay relevance scoring

### 10. Network Analysis & Pivot
- Shodan host lookup (open ports, CVEs, banners)
- GreyNoise classification (internet noise vs. targeted)
- ASN/BGP lookup with bulletproof hosting detection
- Reverse IP pivot (domains on same host)
- C2 beacon detection from connection logs (statistical interval analysis)

### 11. Case Manager
- Create named investigation cases with severity and analyst info
- Add IOCs with verdicts (malicious/suspicious/FP/under investigation)
- Add analyst notes and timeline entries
- View full case with color-coded verdict display
- Export as JSON or Markdown report
- Shift handover report generator

### 12. SIEM / SOAR Toolbox
- **SIEM Hunt Queries:** Splunk, Elastic/Kibana, Microsoft Sentinel, IBM QRadar
- **Sigma Rule Generator:** Vendor-neutral YAML detection rules
- **Firewall Rule Generator:** iptables, Windows Defender, Cisco ASA, pfSense
- **Investigation Playbooks:** Step-by-step guided workflows for phishing, malicious IP, ransomware

---

## 🔐 Security Features

- API keys encrypted with **Fernet symmetric encryption**
- Tamper-evident **audit log** (every action timestamped)
- No sensitive data stored in plaintext
- Local-only execution — no cloud dependency

---

## 🗺️ Roadmap / Future Enhancements

- [ ] ML-based phishing prediction engine
- [ ] PCAP file analysis (JA3/JA3S fingerprinting)
- [ ] STIX/TAXII feed ingestion
- [ ] Web dashboard (Flask + React)
- [ ] SIEM platform integration (direct alert ingestion)
- [ ] Cron-based automated brand monitoring
- [ ] Dark web mention checker (IntelligenceX)

---

## 📚 References

1. VirusTotal API — https://developers.virustotal.com/
2. AbuseIPDB API — https://www.abuseipdb.com/api
3. AlienVault OTX — https://otx.alienvault.com/api
4. ThreatFox API — https://threatfox.abuse.ch/api/
5. MalwareBazaar — https://bazaar.abuse.ch/api/
6. URLScan.io — https://urlscan.io/docs/api/
7. Shodan — https://developer.shodan.io/
8. MITRE ATT&CK — https://attack.mitre.org/
9. Sigma Rules — https://github.com/SigmaHQ/sigma

---

*SEAAT v2.0 — Built for SOC analysts, by Cyber Security students.*
