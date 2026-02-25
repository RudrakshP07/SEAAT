"""
SEAAT Module 10 - Network Analysis & Infrastructure Pivot
Features: Shodan lookup, ASN analysis, IP-to-infra pivot,
          GreyNoise check, BGP route check, C2 beacon pattern detection
"""

import re
from core.banner import section_header, info, success, warn, error, result
from core import api_helper, config_manager, audit_log


# ─── Shodan ────────────────────────────────────────────────────────────────────

def shodan_lookup(ip: str):
    key = config_manager.get_key("shodan")
    if not key:
        warn("Shodan API key not configured - using limited host info")
        data = api_helper.get(f"https://internetdb.shodan.io/{ip}",
                              cache_key=f"shodan_idb_{ip}")
        if "_error" not in data:
            result("Open Ports:", ", ".join(str(p) for p in data.get("ports", [])))
            result("CPEs:", ", ".join(data.get("cpes", [])[:3]) or "None")
            result("Tags:", ", ".join(data.get("tags", [])) or "None")
            result("Vulns:", ", ".join(data.get("vulns", [])[:5]) or "None")
            if data.get("vulns"):
                warn(f"Known vulnerabilities: {', '.join(data['vulns'][:5])}")
        else:
            error(data["_error"])
        return

    data = api_helper.get(f"https://api.shodan.io/shodan/host/{ip}?key={key}",
                          cache_key=f"shodan_{ip}")
    if "_error" in data:
        error(data["_error"])
        return

    result("Organization:", data.get("org", "N/A"))
    result("ISP:", data.get("isp", "N/A"))
    result("Country:", data.get("country_name", "N/A"))
    result("OS:", data.get("os", "N/A"))
    result("Open Ports:", ", ".join(str(p) for p in data.get("ports", [])))
    result("Hostnames:", ", ".join(data.get("hostnames", [])[:3]) or "None")
    result("Domains:", ", ".join(data.get("domains", [])[:3]) or "None")

    vulns = data.get("vulns", [])
    if vulns:
        warn(f"Known CVEs ({len(vulns)}): {', '.join(list(vulns)[:5])}")
    else:
        success("No known CVEs via Shodan")

    audit_log.log("SHODAN_LOOKUP", ip)


# ─── GreyNoise ─────────────────────────────────────────────────────────────────

def greynoise_check(ip: str):
    """Check if IP is internet noise vs. targeted scanning."""
    info(f"Checking GreyNoise for: {ip}")
    data = api_helper.get(f"https://api.greynoise.io/v3/community/{ip}",
                          headers={"Accept": "application/json"},
                          cache_key=f"greynoise_{ip}")
    if "_error" in data:
        # Try unauthenticated
        warn(f"GreyNoise: {data['_error']}")
        return

    result("IP:", data.get("ip"))
    result("Noise:", str(data.get("noise", "N/A")))
    result("Riot:", str(data.get("riot", "N/A")))
    result("Classification:", data.get("classification", "N/A"))
    result("Name:", data.get("name", "N/A"))
    result("Last Seen:", data.get("last_seen", "N/A"))

    if data.get("noise"):
        warn("IP is INTERNET NOISE - seen mass-scanning the internet")
    if data.get("riot"):
        success("IP is a known benign service (RIOT)")

    audit_log.log("GREYNOISE", ip)


# ─── ASN Lookup ────────────────────────────────────────────────────────────────

def asn_lookup(query: str):
    """Look up ASN information for an IP or ASN number."""
    info(f"ASN lookup: {query}")
    data = api_helper.get(f"https://api.iptoasn.com/v1/as/ip/{query}",
                          cache_key=f"asn_{query}")
    if "_error" not in data:
        result("ASN:",          str(data.get("as_number", "N/A")))
        result("AS Name:",      data.get("as_description", "N/A"))
        result("Country:",      data.get("as_country_code", "N/A"))
        result("First IP:",     data.get("first_ip", "N/A"))
        result("Last IP:",      data.get("last_ip", "N/A"))

        # Bulletproof hosting ASNs (simplified list)
        BULLETPROOF_ASNS = {
            "AS3842", "AS48715", "AS62282", "AS204957", "AS9009",
            "AS43289", "AS49453", "AS51852",
        }
        asn_str = f"AS{data.get('as_number', '')}"
        if asn_str in BULLETPROOF_ASNS:
            warn(f"{asn_str} is associated with bulletproof hosting!")
    else:
        # Fallback to ipinfo
        data2 = api_helper.get(f"https://ipinfo.io/{query}/json",
                               cache_key=f"ipinfo_asn_{query}")
        if "_error" not in data2:
            result("Org/ASN:", data2.get("org", "N/A"))
            result("Country:", data2.get("country", "N/A"))
        else:
            error(data["_error"])

    audit_log.log("ASN_LOOKUP", query)


# ─── Reverse IP / Infrastructure Pivot ────────────────────────────────────────

def reverse_ip_pivot(ip: str):
    """Find other domains hosted on the same IP (reverse IP lookup)."""
    info(f"Reverse IP pivot for: {ip}")
    # Using HackerTarget free API
    data_raw = api_helper.get(f"https://api.hackertarget.com/reverseiplookup/?q={ip}")
    if "_error" in data_raw:
        error(data_raw["_error"])
        return
    # HackerTarget returns plain text, not JSON - handle via requests
    try:
        import requests
        resp = requests.get(f"https://api.hackertarget.com/reverseiplookup/?q={ip}", timeout=10)
        domains = [d.strip() for d in resp.text.splitlines() if d.strip() and "." in d]
        result("Domains on same IP:", str(len(domains)))
        for d in domains[:20]:
            print(f"    • {d}")
        if len(domains) > 20:
            print(f"    ... and {len(domains) - 20} more")
    except Exception as e:
        error(str(e))

    audit_log.log("REVERSE_IP", ip)


# ─── C2 Beacon Detection ───────────────────────────────────────────────────────

def beacon_detect(log_text: str):
    """
    Analyze network connection log for beaconing behavior.
    Expects lines in format: timestamp destination_ip [port]
    e.g.  2024-01-15T10:00:00 8.8.8.8 443
    """
    import datetime
    import statistics

    info("Analyzing for C2 beaconing patterns...")

    # Parse lines
    pattern = re.compile(r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})\s+([\d.]+)")
    connections = {}

    for line in log_text.splitlines():
        m = pattern.search(line)
        if m:
            ts_str, ip = m.group(1), m.group(2)
            try:
                ts = datetime.datetime.fromisoformat(ts_str.replace(" ", "T"))
                connections.setdefault(ip, []).append(ts)
            except Exception:
                pass

    if not connections:
        warn("No parseable connection entries found. Expected format: TIMESTAMP DEST_IP")
        return

    result("Unique Destinations:", str(len(connections)))
    beacon_candidates = []

    for ip, timestamps in connections.items():
        if len(timestamps) < 3:
            continue
        timestamps.sort()
        intervals = [(timestamps[i+1] - timestamps[i]).total_seconds()
                     for i in range(len(timestamps) - 1)]
        mean_interval = statistics.mean(intervals)
        stdev = statistics.stdev(intervals) if len(intervals) > 1 else 0
        jitter_pct = (stdev / mean_interval * 100) if mean_interval > 0 else 0

        if jitter_pct < 10 and len(timestamps) >= 5:
            beacon_candidates.append({
                "ip": ip, "connections": len(timestamps),
                "mean_interval_s": round(mean_interval, 1),
                "jitter_pct": round(jitter_pct, 1),
            })

    if beacon_candidates:
        warn(f"POTENTIAL C2 BEACONS DETECTED ({len(beacon_candidates)}):")
        for c in beacon_candidates:
            print(f"\n    IP: {c['ip']}")
            print(f"    Connections: {c['connections']}")
            print(f"    Mean Interval: {c['mean_interval_s']}s")
            print(f"    Jitter: {c['jitter_pct']}%")
    else:
        success("No obvious beaconing patterns detected")

    audit_log.log("BEACON_DETECT", f"{len(connections)} destinations")


def menu():
    section_header("NETWORK ANALYSIS & PIVOT")
    print("  [1] Shodan Host Lookup")
    print("  [2] GreyNoise IP Check (noise vs. targeted)")
    print("  [3] ASN / BGP Lookup")
    print("  [4] Reverse IP Pivot (domains on same host)")
    print("  [5] C2 Beacon Detector (analyze connection logs)")
    print("  [0] Back\n")

    choice = input("  Select: ").strip()

    if choice == "1":
        ip = input("  Enter IP address: ").strip()
        shodan_lookup(ip)

    elif choice == "2":
        ip = input("  Enter IP address: ").strip()
        greynoise_check(ip)

    elif choice == "3":
        q = input("  Enter IP or AS number: ").strip()
        asn_lookup(q)

    elif choice == "4":
        ip = input("  Enter IP address: ").strip()
        reverse_ip_pivot(ip)

    elif choice == "5":
        print("  Paste connection log (end with blank line):")
        print("  Expected format: YYYY-MM-DDTHH:MM:SS DEST_IP [port]")
        lines = []
        while True:
            line = input()
            if not line:
                break
            lines.append(line)
        if lines:
            beacon_detect("\n".join(lines))

    elif choice == "0":
        return
    else:
        warn("Invalid option")
