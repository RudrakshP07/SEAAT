"""
SEAAT Module 1 - Reputation / Blocklist Check
Supports: IP, Domain, URL, MD5/SHA1/SHA256 hash
APIs: VirusTotal, AbuseIPDB, AlienVault OTX, APIVoid
"""

import re
import os
from core.banner import section_header, info, success, warn, error, result
from core import config_manager, api_helper, audit_log


# ── IOC type detection ──────────────────────────────────────────────────────

def detect_type(ioc: str) -> str:
    ioc = ioc.strip()
    ip_pattern   = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
    md5_pattern  = re.compile(r"^[a-fA-F0-9]{32}$")
    sha1_pattern = re.compile(r"^[a-fA-F0-9]{40}$")
    sha256_pattern = re.compile(r"^[a-fA-F0-9]{64}$")

    if ip_pattern.match(ioc):
        return "ip"
    if md5_pattern.match(ioc) or sha1_pattern.match(ioc) or sha256_pattern.match(ioc):
        return "hash"
    if ioc.startswith("http://") or ioc.startswith("https://"):
        return "url"
    if re.match(r"^[\w\.-]+\.[a-zA-Z]{2,}$", ioc):
        return "domain"
    return "unknown"


# ── VirusTotal ───────────────────────────────────────────────────────────────

def vt_check(ioc: str, ioc_type: str) -> dict:
    key = config_manager.get_key("virustotal")
    if not key:
        return {"_error": "VirusTotal API key not configured"}

    headers = {"x-apikey": key}
    endpoints = {
        "ip":     f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}",
        "domain": f"https://www.virustotal.com/api/v3/domains/{ioc}",
        "url":    None,  # URL requires encode step
        "hash":   f"https://www.virustotal.com/api/v3/files/{ioc}",
    }

    if ioc_type == "url":
        import base64
        url_id = base64.urlsafe_b64encode(ioc.encode()).decode().strip("=")
        endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    else:
        endpoint = endpoints.get(ioc_type)

    if not endpoint:
        return {"_error": "Unsupported IOC type for VirusTotal"}

    data = api_helper.get(endpoint, headers=headers,
                          cache_key=f"vt_{ioc_type}_{ioc}")
    if "_error" in data:
        return data

    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    return {
        "malicious":   stats.get("malicious", 0),
        "suspicious":  stats.get("suspicious", 0),
        "harmless":    stats.get("harmless", 0),
        "undetected":  stats.get("undetected", 0),
        "reputation":  attrs.get("reputation", "N/A"),
        "community_score": attrs.get("total_votes", {}).get("malicious", "N/A"),
    }


# ── AbuseIPDB ────────────────────────────────────────────────────────────────

def abuseipdb_check(ip: str) -> dict:
    key = config_manager.get_key("abuseipdb")
    if not key:
        return {"_error": "AbuseIPDB API key not configured"}

    headers = {"Key": key, "Accept": "application/json"}
    params  = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": True}
    data = api_helper.get("https://api.abuseipdb.com/api/v2/check",
                          headers=headers, params=params,
                          cache_key=f"abuse_{ip}")
    if "_error" in data:
        return data

    d = data.get("data", {})
    return {
        "abuse_score":     d.get("abuseConfidenceScore", 0),
        "country":         d.get("countryCode", "N/A"),
        "isp":             d.get("isp", "N/A"),
        "total_reports":   d.get("totalReports", 0),
        "last_reported":   d.get("lastReportedAt", "N/A"),
        "is_whitelisted":  d.get("isWhitelisted", False),
        "usage_type":      d.get("usageType", "N/A"),
    }


# ── AlienVault OTX ───────────────────────────────────────────────────────────

def otx_check(ioc: str, ioc_type: str) -> dict:
    key = config_manager.get_key("alienvault_otx")
    if not key:
        return {"_error": "AlienVault OTX API key not configured"}

    headers = {"X-OTX-API-KEY": key}
    section_map = {
        "ip":     f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ioc}/general",
        "domain": f"https://otx.alienvault.com/api/v1/indicators/domain/{ioc}/general",
        "url":    f"https://otx.alienvault.com/api/v1/indicators/url/{ioc}/general",
        "hash":   f"https://otx.alienvault.com/api/v1/indicators/file/{ioc}/general",
    }
    endpoint = section_map.get(ioc_type)
    if not endpoint:
        return {"_error": "Unsupported type for OTX"}

    data = api_helper.get(endpoint, headers=headers,
                          cache_key=f"otx_{ioc_type}_{ioc}")
    if "_error" in data:
        return data

    pulses = data.get("pulse_info", {})
    return {
        "pulse_count":  pulses.get("count", 0),
        "tags":         ", ".join(pulses.get("tags", [])[:5]) or "None",
        "references":   pulses.get("references", [])[:3],
    }


# ── APIVoid ──────────────────────────────────────────────────────────────────

def apivoid_domain_check(domain: str) -> dict:
    key = config_manager.get_key("apivoid")
    if not key:
        return {"_error": "APIVoid API key not configured"}

    url  = f"https://endpoint.apivoid.com/domainbl/v1/pay-as-you-go/?key={key}&host={domain}"
    data = api_helper.get(url, cache_key=f"apivoid_domain_{domain}")
    if "_error" in data:
        return data

    report = data.get("data", {}).get("report", {})
    return {
        "blacklists_detected": report.get("blacklists", {}).get("detections", 0),
        "blacklists_checked":  report.get("blacklists", {}).get("engines_count", 0),
        "alexa_rank":          report.get("alexa", {}).get("rank", "N/A"),
        "is_risky":            report.get("blacklists", {}).get("is_listed", False),
    }


# ── Risk Score Aggregator ─────────────────────────────────────────────────────

def compute_risk_score(vt: dict, abuse: dict, otx: dict) -> int:
    score = 0
    # VT contribution
    mal = vt.get("malicious", 0)
    sus = vt.get("suspicious", 0)
    if mal >= 10:   score += 40
    elif mal >= 5:  score += 25
    elif mal >= 1:  score += 15
    if sus >= 3:    score += 10

    # AbuseIPDB contribution
    abuse_s = abuse.get("abuse_score", 0)
    if isinstance(abuse_s, int):
        score += min(30, abuse_s // 3)

    # OTX contribution
    pulses = otx.get("pulse_count", 0)
    if pulses >= 10:  score += 20
    elif pulses >= 3: score += 10
    elif pulses >= 1: score += 5

    return min(100, score)


def risk_label(score: int) -> str:
    if score >= 75: return "CRITICAL"
    if score >= 50: return "HIGH"
    if score >= 25: return "MEDIUM"
    if score >= 10: return "LOW"
    return "CLEAN"


def risk_color(score: int):
    from colorama import Fore, Style
    if score >= 75: return Fore.RED + Style.BRIGHT
    if score >= 50: return Fore.RED
    if score >= 25: return Fore.YELLOW
    if score >= 10: return Fore.CYAN
    return Fore.GREEN


# ── Display ──────────────────────────────────────────────────────────────────

def display_results(ioc: str, ioc_type: str, vt: dict, abuse: dict, otx: dict, apivoid: dict):
    try:
        from colorama import Fore, Style
    except ImportError:
        class _D:
            def __getattr__(self, n): return ""
        Fore = Style = _D()

    score = compute_risk_score(vt, abuse, otx)
    label = risk_label(score)
    color = risk_color(score)

    print(f"\n  {'─'*60}")
    print(f"  IOC        : {Fore.YELLOW}{ioc}{Style.RESET_ALL}")
    print(f"  Type       : {ioc_type.upper()}")
    print(color + f"  Risk Score : {score}/100  [{label}]" + Style.RESET_ALL)
    print(f"  {'─'*60}")

    if "_error" not in vt:
        print(f"\n  {Fore.CYAN}[ VirusTotal ]{Style.RESET_ALL}")
        result("Malicious Detections:", str(vt.get("malicious", "?")))
        result("Suspicious:",           str(vt.get("suspicious", "?")))
        result("Harmless:",             str(vt.get("harmless", "?")))
        result("Reputation Score:",     str(vt.get("reputation", "?")))
    else:
        warn(f"VirusTotal: {vt['_error']}")

    if "_error" not in abuse:
        print(f"\n  {Fore.CYAN}[ AbuseIPDB ]{Style.RESET_ALL}")
        result("Abuse Score:",    str(abuse.get("abuse_score", "?")))
        result("Country:",        str(abuse.get("country", "?")))
        result("ISP:",            str(abuse.get("isp", "?")))
        result("Total Reports:",  str(abuse.get("total_reports", "?")))
        result("Last Reported:",  str(abuse.get("last_reported", "?")))
    elif ioc_type == "ip":
        warn(f"AbuseIPDB: {abuse['_error']}")

    if "_error" not in otx:
        print(f"\n  {Fore.CYAN}[ AlienVault OTX ]{Style.RESET_ALL}")
        result("Pulse Count:",  str(otx.get("pulse_count", "?")))
        result("Tags:",         str(otx.get("tags", "?")))
    else:
        warn(f"OTX: {otx['_error']}")

    if "_error" not in apivoid and ioc_type == "domain":
        print(f"\n  {Fore.CYAN}[ APIVoid ]{Style.RESET_ALL}")
        result("Blacklists Detected:", str(apivoid.get("blacklists_detected", "?")))
        result("Blacklists Checked:",  str(apivoid.get("blacklists_checked", "?")))
        result("Is Risky:",            str(apivoid.get("is_risky", "?")))

    print(f"\n  {'─'*60}")


# ── Menu ─────────────────────────────────────────────────────────────────────

def single_check(ioc: str):
    ioc = ioc.strip().lower()
    ioc_type = detect_type(ioc)

    if ioc_type == "unknown":
        error("Could not determine IOC type. Please enter a valid IP, domain, URL, or hash.")
        return

    info(f"Detected type: {ioc_type.upper()}")
    info("Querying threat intelligence sources...")

    vt      = vt_check(ioc, ioc_type)
    abuse   = abuseipdb_check(ioc) if ioc_type == "ip" else {}
    otx     = otx_check(ioc, ioc_type)
    apivoid = apivoid_domain_check(ioc) if ioc_type == "domain" else {}

    display_results(ioc, ioc_type, vt, abuse, otx, apivoid)
    audit_log.log("REPUTATION_CHECK", f"{ioc_type}:{ioc}")


def bulk_check(filepath: str):
    if not os.path.exists(filepath):
        error(f"File not found: {filepath}")
        return
    with open(filepath) as f:
        iocs = [line.strip() for line in f if line.strip()]
    info(f"Loaded {len(iocs)} IOCs from file")
    for ioc in iocs:
        print(f"\n  {'═'*60}")
        single_check(ioc)


def menu():
    section_header("REPUTATION / BLOCKLIST CHECK")
    print("  [1] Single IOC Check")
    print("  [2] Bulk Check (from file)")
    print("  [0] Back\n")
    choice = input("  Select: ").strip()

    if choice == "1":
        ioc = input("\n  Enter IP / Domain / URL / Hash: ").strip()
        if ioc:
            single_check(ioc)
    elif choice == "2":
        path = input("\n  Enter file path (one IOC per line): ").strip()
        bulk_check(path)
    elif choice == "0":
        return
    else:
        warn("Invalid option")
