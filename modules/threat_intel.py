"""
SEAAT Module 9 - Threat Intelligence Correlation
Features: AlienVault OTX pulses, ThreatFox IOC lookup, MITRE ATT&CK mapping
"""

from core.banner import section_header, info, success, warn, error, result
from core import api_helper, config_manager, audit_log


# ─── ThreatFox ────────────────────────────────────────────────────────────────

def threatfox_lookup(ioc: str, ioc_type: str = "url"):
    """Query ThreatFox for IOC intelligence (no API key required for basic queries)."""
    info(f"Querying ThreatFox for: {ioc}")
    type_map = {
        "ip": "ip:port",
        "domain": "domain",
        "url": "url",
        "hash": "payload",
    }
    query_type = type_map.get(ioc_type, "url")
    payload = {"query": "search_ioc", "search_term": ioc}
    data = api_helper.post("https://threatfox-api.abuse.ch/api/v1/",
                           json_body=payload)
    if "_error" in data:
        error(data["_error"])
        return

    query_status = data.get("query_status")
    if query_status == "no_result":
        success("No results in ThreatFox for this IOC")
        return
    if query_status == "ok":
        items = data.get("data", [])
        result("ThreatFox Results:", str(len(items)))
        for item in items[:5]:
            print(f"\n    ID:          {item.get('id', 'N/A')}")
            print(f"    IOC:         {item.get('ioc', 'N/A')}")
            print(f"    Threat Type: {item.get('threat_type', 'N/A')}")
            print(f"    Malware:     {item.get('malware', 'N/A')}")
            print(f"    Confidence:  {item.get('confidence_level', 'N/A')}%")
            print(f"    First Seen:  {item.get('first_seen', 'N/A')}")
    audit_log.log("THREATFOX", ioc)


# ─── OTX Pulse Search ─────────────────────────────────────────────────────────

def otx_pulse_search(query: str):
    """Search AlienVault OTX for threat pulses related to a query."""
    key = config_manager.get_key("alienvault_otx")
    if not key:
        warn("AlienVault OTX API key not configured")
        return
    headers = {"X-OTX-API-KEY": key}
    info(f"Searching OTX pulses for: {query}")
    data = api_helper.get(
        f"https://otx.alienvault.com/api/v1/search/pulses?q={query}&limit=5",
        headers=headers,
        cache_key=f"otx_pulse_{query}"
    )
    if "_error" in data:
        error(data["_error"])
        return
    pulses = data.get("results", [])
    result("Pulses Found:", str(len(pulses)))
    for p in pulses:
        print(f"\n    Name:     {p.get('name', 'N/A')}")
        print(f"    Author:   {p.get('author_name', 'N/A')}")
        print(f"    Tags:     {', '.join(p.get('tags', [])[:5])}")
        print(f"    TLP:      {p.get('tlp', 'N/A')}")
        print(f"    Modified: {p.get('modified', 'N/A')[:10]}")
    audit_log.log("OTX_PULSE_SEARCH", query)


# ─── MITRE ATT&CK ─────────────────────────────────────────────────────────────

# Embedded compact ATT&CK tactic-technique reference
ATTACK_TACTICS = {
    "TA0001": ("Initial Access", ["T1566", "T1078", "T1190", "T1133"]),
    "TA0002": ("Execution", ["T1059", "T1203", "T1106"]),
    "TA0003": ("Persistence", ["T1547", "T1053", "T1078"]),
    "TA0004": ("Privilege Escalation", ["T1548", "T1134", "T1078"]),
    "TA0005": ("Defense Evasion", ["T1055", "T1027", "T1562"]),
    "TA0006": ("Credential Access", ["T1110", "T1003", "T1552"]),
    "TA0007": ("Discovery", ["T1087", "T1083", "T1018"]),
    "TA0008": ("Lateral Movement", ["T1021", "T1550"]),
    "TA0009": ("Collection", ["T1005", "T1114", "T1560"]),
    "TA0010": ("Exfiltration", ["T1048", "T1041", "T1567"]),
    "TA0011": ("Command & Control", ["T1071", "T1090", "T1102"]),
    "TA0040": ("Impact", ["T1486", "T1489", "T1499"]),
}

TECHNIQUE_NAMES = {
    "T1566": "Phishing",
    "T1078": "Valid Accounts",
    "T1190": "Exploit Public-Facing Application",
    "T1133": "External Remote Services",
    "T1059": "Command and Scripting Interpreter",
    "T1203": "Exploitation for Client Execution",
    "T1106": "Native API",
    "T1547": "Boot or Logon Autostart Execution",
    "T1053": "Scheduled Task/Job",
    "T1548": "Abuse Elevation Control Mechanism",
    "T1134": "Access Token Manipulation",
    "T1055": "Process Injection",
    "T1027": "Obfuscated Files or Information",
    "T1562": "Impair Defenses",
    "T1110": "Brute Force",
    "T1003": "OS Credential Dumping",
    "T1552": "Unsecured Credentials",
    "T1087": "Account Discovery",
    "T1083": "File and Directory Discovery",
    "T1018": "Remote System Discovery",
    "T1021": "Remote Services",
    "T1550": "Use Alternate Authentication Material",
    "T1005": "Data from Local System",
    "T1114": "Email Collection",
    "T1560": "Archive Collected Data",
    "T1048": "Exfiltration Over Alternative Protocol",
    "T1041": "Exfiltration Over C2 Channel",
    "T1567": "Exfiltration Over Web Service",
    "T1071": "Application Layer Protocol",
    "T1090": "Proxy",
    "T1102": "Web Service",
    "T1486": "Data Encrypted for Impact (Ransomware)",
    "T1489": "Service Stop",
    "T1499": "Endpoint Denial of Service",
}


def show_attack_matrix():
    """Display a compact MITRE ATT&CK reference."""
    try:
        from colorama import Fore, Style
    except ImportError:
        class _D:
            def __getattr__(self, n): return ""
        Fore = Style = _D()

    print(f"\n  {Fore.CYAN}{Style.BRIGHT}MITRE ATT&CK Tactics Overview{Style.RESET_ALL}\n")
    for tactic_id, (name, techniques) in ATTACK_TACTICS.items():
        tech_str = ", ".join(f"{t}({TECHNIQUE_NAMES.get(t, '?')})" for t in techniques[:3])
        print(f"  {Fore.YELLOW}{tactic_id}{Style.RESET_ALL} {name:<35} {tech_str}")
    print()


def attack_lookup(query: str):
    """Search MITRE ATT&CK by technique ID or keyword."""
    query_upper = query.upper()
    # Direct technique ID lookup
    if query_upper in TECHNIQUE_NAMES:
        result("Technique ID:", query_upper)
        result("Name:", TECHNIQUE_NAMES[query_upper])
        result("Reference:", f"https://attack.mitre.org/techniques/{query_upper}/")
        # Find parent tactic
        for tactic_id, (tactic_name, techniques) in ATTACK_TACTICS.items():
            if query_upper in techniques:
                result("Tactic:", f"{tactic_id} - {tactic_name}")
        return

    # Keyword search
    matches = [(tid, name) for tid, name in TECHNIQUE_NAMES.items()
               if query.lower() in name.lower()]
    if matches:
        info(f"Found {len(matches)} matching techniques:")
        for tid, name in matches:
            print(f"    {tid}: {name}")
    else:
        warn(f"No ATT&CK techniques found matching: {query}")

    audit_log.log("ATTACK_LOOKUP", query)


# ─── IOC Decay / Age Scoring ───────────────────────────────────────────────────

def ioc_age_score(ioc: str, first_seen_date: str) -> dict:
    """Score IOC relevance based on age (IOC decay model)."""
    import datetime
    try:
        seen = datetime.datetime.fromisoformat(first_seen_date[:10])
        age_days = (datetime.datetime.now() - seen).days
        if age_days <= 7:   score = 100; label = "VERY FRESH"
        elif age_days <= 30: score = 80; label = "FRESH"
        elif age_days <= 90: score = 60; label = "RECENT"
        elif age_days <= 180: score = 40; label = "AGING"
        elif age_days <= 365: score = 20; label = "STALE"
        else:               score = 5;  label = "EXPIRED"
        return {"age_days": age_days, "relevance_score": score, "label": label}
    except Exception as e:
        return {"error": str(e)}


def menu():
    section_header("THREAT INTELLIGENCE CORRELATION")
    print("  [1] ThreatFox IOC Lookup (free)")
    print("  [2] AlienVault OTX Pulse Search")
    print("  [3] MITRE ATT&CK Technique Lookup")
    print("  [4] MITRE ATT&CK Tactics Overview")
    print("  [5] IOC Age / Decay Score Calculator")
    print("  [0] Back\n")

    choice = input("  Select: ").strip()

    if choice == "1":
        ioc = input("  Enter IOC: ").strip()
        ioc_type = input("  IOC type [ip/domain/url/hash]: ").strip().lower() or "url"
        threatfox_lookup(ioc, ioc_type)

    elif choice == "2":
        query = input("  Search query (threat actor / malware name / IOC): ").strip()
        otx_pulse_search(query)

    elif choice == "3":
        q = input("  Enter technique ID (T1566) or keyword (phishing): ").strip()
        attack_lookup(q)

    elif choice == "4":
        show_attack_matrix()

    elif choice == "5":
        ioc = input("  Enter IOC: ").strip()
        date = input("  First seen date (YYYY-MM-DD): ").strip()
        score = ioc_age_score(ioc, date)
        if "error" not in score:
            result("Age (days):", str(score["age_days"]))
            result("Relevance Score:", f"{score['relevance_score']}/100")
            result("Label:", score["label"])
        else:
            error(score["error"])

    elif choice == "0":
        return
    else:
        warn("Invalid option")
