"""
SEAAT Module 12 - SIEM / SOAR Toolbox
Features: Sigma Rule Generator, Splunk/Elastic/Sentinel query generator,
          Firewall rule generator, Playbook engine (YAML-based)
"""

import os
import datetime
from core.banner import section_header, info, success, warn, error, result
from core import audit_log


# ─── SIEM Query Generator ─────────────────────────────────────────────────────

SIEM_TEMPLATES = {
    "splunk": {
        "ip":     'index=* (src_ip="{IOC}" OR dest_ip="{IOC}" OR src="{IOC}" OR dest="{IOC}")',
        "domain": 'index=* (url="*{IOC}*" OR query="{IOC}" OR hostname="{IOC}")',
        "url":    'index=* url="{IOC}"',
        "hash":   'index=* (file_hash="{IOC}" OR md5="{IOC}" OR sha256="{IOC}")',
        "email":  'index=* (from="{IOC}" OR sender="{IOC}" OR recipient="{IOC}")',
    },
    "elastic": {
        "ip":     '(source.ip: "{IOC}" OR destination.ip: "{IOC}" OR network.destination.ip: "{IOC}")',
        "domain": '(url.domain: "{IOC}" OR dns.question.name: "{IOC}" OR host.name: "{IOC}")',
        "url":    'url.full: "{IOC}"',
        "hash":   '(file.hash.md5: "{IOC}" OR file.hash.sha256: "{IOC}")',
        "email":  '(email.from.address: "{IOC}" OR email.to.address: "{IOC}")',
    },
    "sentinel": {
        "ip":     'union isfuzzy=true DeviceNetworkEvents, CommonSecurityLog\n'
                  '| where RemoteIP == "{IOC}" or DestinationIP == "{IOC}"',
        "domain": 'union isfuzzy=true DeviceNetworkEvents, DnsEvents\n'
                  '| where RemoteUrl contains "{IOC}" or Name contains "{IOC}"',
        "url":    'DeviceNetworkEvents | where RemoteUrl contains "{IOC}"',
        "hash":   'DeviceFileEvents | where MD5 == "{IOC}" or SHA256 == "{IOC}"',
        "email":  'EmailEvents | where SenderFromAddress == "{IOC}"',
    },
    "qradar": {
        "ip":     "SELECT * FROM events WHERE sourceip = '{IOC}' OR destinationip = '{IOC}' LAST 7 DAYS",
        "domain": "SELECT * FROM events WHERE \"URL\" LIKE '%{IOC}%' LAST 7 DAYS",
        "hash":   "SELECT * FROM events WHERE \"File Hash\" = '{IOC}' LAST 7 DAYS",
        "email":  "SELECT * FROM events WHERE \"Email/Sender\" = '{IOC}' LAST 7 DAYS",
    },
}


def generate_siem_queries(ioc: str, ioc_type: str):
    """Generate hunt queries for all major SIEM platforms."""
    info(f"Generating SIEM hunt queries for {ioc_type}: {ioc}")
    print()
    for platform, templates in SIEM_TEMPLATES.items():
        template = templates.get(ioc_type)
        if template:
            query = template.replace("{IOC}", ioc)
            print(f"  ── {platform.upper()} {'─'*50}")
            for line in query.splitlines():
                print(f"    {line}")
            print()
    audit_log.log("SIEM_QUERY", f"{ioc_type}:{ioc}")


# ─── Sigma Rule Generator ─────────────────────────────────────────────────────

def generate_sigma_rule(ioc: str, ioc_type: str, title: str = "", description: str = ""):
    """Generate a Sigma detection rule for an IOC."""
    now = datetime.datetime.now().strftime("%Y/%m/%d")
    title = title or f"SEAAT Detection - {ioc_type.upper()}: {ioc}"
    description = description or f"Auto-generated Sigma rule for IOC: {ioc}"

    field_map = {
        "ip":     ("dst_ip", "src_ip"),
        "domain": ("dns.query.name", "url.domain"),
        "url":    ("url.full",),
        "hash":   ("hashes|contains",),
        "email":  ("email.sender",),
    }

    fields = field_map.get(ioc_type, ("value",))
    if len(fields) == 2:
        condition_block = f"    {fields[0]}: '{ioc}'\n    {fields[1]}: '{ioc}'"
        condition = f"  condition: 1 of detection"
    else:
        condition_block = f"    {fields[0]}: '{ioc}'"
        condition = f"  condition: detection"

    sigma = f"""title: {title}
id: seaat-{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}
status: experimental
description: {description}
author: SEAAT Auto-Generator
date: {now}
tags:
    - attack.threat_intel
logsource:
    category: network
    product: zeek
detection:
    detection:
{chr(10).join('        ' + line for line in condition_block.splitlines())}
{condition}
fields:
    - src_ip
    - dst_ip
    - url
    - dns.query.name
falsepositives:
    - Review context before blocking
level: high
"""

    print(f"\n  ── SIGMA RULE {'─'*50}")
    print(sigma)

    save = input("  Save Sigma rule to file? [y/N]: ").strip().lower()
    if save == "y":
        path = input("  Output path (.yml): ").strip()
        with open(path, "w") as f:
            f.write(sigma)
        success(f"Sigma rule saved: {path}")

    audit_log.log("SIGMA_RULE", f"{ioc_type}:{ioc}")
    return sigma


# ─── Firewall Rule Generator ──────────────────────────────────────────────────

def generate_firewall_rules(iocs: list, ioc_type: str):
    """Generate firewall block rules for major platforms."""
    if ioc_type not in ("ip", "domain"):
        warn("Firewall rules only supported for IPs and domains")
        return

    print(f"\n  {'─'*62}")
    print(f"  Firewall Block Rules for {len(iocs)} {ioc_type}(s):\n")

    # iptables
    print("  ── iptables (Linux)")
    for ioc in iocs:
        if ioc_type == "ip":
            print(f"    iptables -A INPUT  -s {ioc} -j DROP")
            print(f"    iptables -A OUTPUT -d {ioc} -j DROP")
        else:
            print(f"    # Block domain: {ioc} (resolve first, then block IP)")

    # Windows Firewall
    print("\n  ── Windows Defender Firewall (PowerShell)")
    for ioc in iocs:
        if ioc_type == "ip":
            print(f'    New-NetFirewallRule -DisplayName "SEAAT-Block-{ioc}" '
                  f'-Direction Inbound -RemoteAddress {ioc} -Action Block')

    # Cisco ASA
    print("\n  ── Cisco ASA")
    for ioc in iocs:
        if ioc_type == "ip":
            print(f"    access-list SEAAT-BLOCK deny ip {ioc} 255.255.255.255 any")

    # pfSense / OPNsense (shell)
    print("\n  ── pfSense / OPNsense (pfctl)")
    for ioc in iocs:
        if ioc_type == "ip":
            print(f"    pfctl -t seaat_blacklist -T add {ioc}")

    # Generic hosts block for domains
    if ioc_type == "domain":
        print("\n  ── /etc/hosts block (Linux/macOS)")
        for ioc in iocs:
            print(f"    0.0.0.0 {ioc}")

    print(f"  {'─'*62}")
    audit_log.log("FIREWALL_RULES", f"{len(iocs)} {ioc_type}s")


# ─── Playbook Engine ──────────────────────────────────────────────────────────

BUILTIN_PLAYBOOKS = {
    "phishing_email": {
        "name": "Phishing Email Triage",
        "steps": [
            ("Extract IOCs from email", "ioc_extractor"),
            ("Analyze email headers", "phishing_analysis.analyze_headers"),
            ("Check sender reputation", "reputation_check"),
            ("Check URLs in body", "reputation_check.url"),
            ("Check attachments", "file_sandbox"),
            ("Tag IOCs and create/update case", "case_manager"),
        ]
    },
    "malicious_ip": {
        "name": "Malicious IP Investigation",
        "steps": [
            ("Check IP reputation (VT + AbuseIPDB + OTX)", "reputation_check"),
            ("Shodan host lookup", "network_analysis.shodan"),
            ("GreyNoise check", "network_analysis.greynoise"),
            ("ASN / ISP lookup", "network_analysis.asn"),
            ("Reverse IP pivot", "network_analysis.reverse_ip"),
            ("Generate SIEM hunt queries", "soar_toolbox.siem"),
            ("Generate firewall block rules", "soar_toolbox.firewall"),
            ("Create case record", "case_manager"),
        ]
    },
    "ransomware_hash": {
        "name": "Ransomware File Analysis",
        "steps": [
            ("Compute file hashes", "file_sandbox.hash"),
            ("VirusTotal file check", "file_sandbox.vt"),
            ("MalwareBazaar lookup", "file_sandbox.mb"),
            ("Static analysis (PE/strings)", "file_sandbox.static"),
            ("ThreatFox IOC lookup", "threat_intel.threatfox"),
            ("Check for C2 indicators", "network_analysis"),
            ("Generate Sigma rule", "soar_toolbox.sigma"),
            ("Create case + tag as CRITICAL", "case_manager"),
        ]
    },
}


def run_playbook(name: str):
    """Display and guide through a named playbook."""
    if name not in BUILTIN_PLAYBOOKS:
        error(f"Unknown playbook: {name}")
        available = ", ".join(BUILTIN_PLAYBOOKS.keys())
        info(f"Available: {available}")
        return

    pb = BUILTIN_PLAYBOOKS[name]
    info(f"Starting playbook: {pb['name']}")
    print(f"\n  Steps to complete:\n")
    for i, (step_name, _module) in enumerate(pb["steps"], 1):
        print(f"    {i:>2}. {step_name}")

    print(f"\n  Use SEAAT menu options to execute each step.")
    print(f"  Recommended workflow: complete each step in order and document findings in Case Manager.\n")
    audit_log.log("PLAYBOOK_RUN", name)


def menu():
    section_header("SIEM / SOAR TOOLBOX")
    print("  [1] SIEM Hunt Query Generator (Splunk/Elastic/Sentinel/QRadar)")
    print("  [2] Sigma Rule Generator")
    print("  [3] Firewall Block Rule Generator")
    print("  [4] Run Investigation Playbook")
    print("  [5] Show Available Playbooks")
    print("  [0] Back\n")

    choice = input("  Select: ").strip()

    if choice == "1":
        ioc = input("  Enter IOC: ").strip()
        ioc_type = input("  IOC type [ip/domain/url/hash/email]: ").strip().lower()
        generate_siem_queries(ioc, ioc_type)

    elif choice == "2":
        ioc = input("  Enter IOC: ").strip()
        ioc_type = input("  IOC type [ip/domain/url/hash/email]: ").strip().lower()
        title = input("  Rule title (leave blank for auto): ").strip()
        desc  = input("  Description (leave blank for auto): ").strip()
        generate_sigma_rule(ioc, ioc_type, title, desc)

    elif choice == "3":
        raw = input("  Enter IOC(s) comma-separated: ").strip()
        iocs = [i.strip() for i in raw.split(",") if i.strip()]
        ioc_type = input("  IOC type [ip/domain]: ").strip().lower()
        generate_firewall_rules(iocs, ioc_type)

    elif choice == "4":
        print("  Available playbooks:")
        for k, v in BUILTIN_PLAYBOOKS.items():
            print(f"    [{k}] {v['name']}")
        name = input("  Enter playbook name: ").strip()
        run_playbook(name)

    elif choice == "5":
        for k, v in BUILTIN_PLAYBOOKS.items():
            print(f"\n  [{k}] {v['name']}")
            for i, (step, _) in enumerate(v["steps"], 1):
                print(f"    {i}. {step}")

    elif choice == "0":
        return
    else:
        warn("Invalid option")
