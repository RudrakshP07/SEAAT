"""
SEAAT Module 7 - Brand Monitoring & Analysis
Features: Typosquatting, Certificate Transparency (crt.sh),
          Lookalike domain scoring, Geo check, UI probe, URL reputation
"""

import re
import itertools
from core.banner import section_header, info, success, warn, error, result
from core import api_helper, audit_log


# ─── Typosquatting ─────────────────────────────────────────────────────────────

HOMOGLYPHS = {
    "a": ["а", "ạ", "ă"], "e": ["е", "ė"], "i": ["і", "ï", "1", "l"],
    "o": ["о", "0", "ο"], "u": ["υ"], "l": ["1", "I"], "g": ["q"],
    "c": ["с", "ç"], "s": ["ѕ"], "n": ["ν"], "t": ["τ"],
}

COMMON_TLDS = [".com", ".net", ".org", ".info", ".co", ".io", ".biz",
               ".online", ".site", ".xyz", ".club", ".shop"]


def generate_typos(domain: str) -> list:
    """Generate common typosquatting permutations."""
    parts = domain.rsplit(".", 1)
    base  = parts[0]
    tld   = "." + parts[1] if len(parts) > 1 else ".com"

    typos = set()

    # 1. Character deletion
    for i in range(len(base)):
        typos.add(base[:i] + base[i+1:] + tld)

    # 2. Character transposition
    for i in range(len(base) - 1):
        t = list(base)
        t[i], t[i+1] = t[i+1], t[i]
        typos.add("".join(t) + tld)

    # 3. Character substitution (keyboard proximity)
    keyboard_adj = {"a":"sqwze","b":"vghn","c":"xdfv","d":"srfce","e":"wsdr",
                    "f":"rdgce","g":"ftyhb","h":"gyunj","i":"ujko","j":"huikm",
                    "k":"jilo","l":"kop","m":"njk","n":"bmhj","o":"ikpl",
                    "p":"ol","q":"wa","r":"edft","s":"awedz","t":"rfgy",
                    "u":"yhij","v":"cfgb","w":"qsae","x":"zsdc","y":"tghu","z":"axs"}
    for i, c in enumerate(base):
        for adj in keyboard_adj.get(c, ""):
            typos.add(base[:i] + adj + base[i+1:] + tld)

    # 4. TLD swaps
    for alt_tld in COMMON_TLDS:
        if alt_tld != tld:
            typos.add(base + alt_tld)

    # 5. Common prefixes/suffixes
    for prefix in ["my", "the", "get", "go", "best", "login", "secure"]:
        typos.add(prefix + base + tld)
    for suffix in ["-login", "-secure", "-verify", "-account", "-support"]:
        typos.add(base + suffix + tld)

    return sorted(typos - {domain})


def check_typosquats(domain: str, check_dns: bool = False):
    info(f"Generating typosquatting permutations for: {domain}")
    typos = generate_typos(domain)
    info(f"Generated {len(typos)} permutations")

    if not check_dns:
        print(f"\n  Sample permutations (first 30):")
        for t in typos[:30]:
            print(f"    {t}")
        return

    import socket
    registered = []
    info("Checking DNS registration (this may take a moment)...")
    for typo in typos[:50]:  # Limit to avoid rate-limits
        try:
            socket.gethostbyname(typo)
            registered.append(typo)
        except Exception:
            pass

    if registered:
        warn(f"REGISTERED TYPOSQUATS FOUND ({len(registered)}):")
        for r in registered:
            print(f"    ⚠  {r}")
    else:
        success("No registered typosquats found in sample")

    audit_log.log("TYPOSQUAT_CHECK", domain)


# ─── Certificate Transparency ──────────────────────────────────────────────────

def cert_transparency(domain: str):
    """Find subdomains/certs via crt.sh."""
    info(f"Querying Certificate Transparency logs for: {domain}")
    data = api_helper.get(f"https://crt.sh/?q=%.{domain}&output=json",
                          cache_key=f"crt_{domain}")
    if "_error" in data:
        # crt.sh returns a list directly
        error(data["_error"])
        return
    if not isinstance(data, list):
        warn("Unexpected crt.sh response format")
        return

    seen = set()
    entries = []
    for entry in data:
        name = entry.get("name_value", "")
        for sub in name.splitlines():
            sub = sub.strip().lstrip("*.")
            if sub and sub not in seen:
                seen.add(sub)
                entries.append({
                    "domain": sub,
                    "issuer": entry.get("issuer_name", "N/A")[:60],
                    "logged": entry.get("entry_timestamp", "N/A")[:10],
                })

    result("Unique Certificates Found:", str(len(entries)))
    print(f"\n  Recent entries (up to 20):")
    for e in entries[:20]:
        print(f"    {e['logged']}  {e['domain']:<50}  {e['issuer'][:40]}")

    audit_log.log("CERT_TRANSPARENCY", domain)


# ─── Lookalike Scoring ─────────────────────────────────────────────────────────

def levenshtein(s1: str, s2: str) -> int:
    m, n = len(s1), len(s2)
    dp = [[0]*(n+1) for _ in range(m+1)]
    for i in range(m+1): dp[i][0] = i
    for j in range(n+1): dp[0][j] = j
    for i in range(1, m+1):
        for j in range(1, n+1):
            if s1[i-1] == s2[j-1]: dp[i][j] = dp[i-1][j-1]
            else: dp[i][j] = 1 + min(dp[i-1][j], dp[i][j-1], dp[i-1][j-1])
    return dp[m][n]


def lookalike_score(brand: str, suspect: str) -> dict:
    brand_base   = brand.split(".")[0].lower()
    suspect_base = suspect.split(".")[0].lower()
    dist = levenshtein(brand_base, suspect_base)
    max_len = max(len(brand_base), len(suspect_base))
    similarity = (1 - dist / max_len) * 100
    return {
        "brand": brand,
        "suspect": suspect,
        "edit_distance": dist,
        "similarity_pct": round(similarity, 1),
        "verdict": "HIGH RISK" if similarity > 80 else ("MEDIUM RISK" if similarity > 60 else "LOW RISK"),
    }


def geo_check(url: str):
    info(f"Geo check for: {url}")
    try:
        import urllib.parse
        domain = urllib.parse.urlparse(url).netloc or url
        data = api_helper.get(f"https://ipinfo.io/{domain}/json",
                              cache_key=f"geo_{domain}")
        for k in ["country", "region", "city", "org", "hostname"]:
            if k in data:
                result(k.capitalize() + ":", data[k])
    except Exception as e:
        error(str(e))


def menu():
    section_header("BRAND MONITORING & ANALYSIS")
    print("  [1] Typosquatting Detection")
    print("  [2] Certificate Transparency Lookup (crt.sh)")
    print("  [3] Lookalike Domain Scoring")
    print("  [4] Geography / GeoIP of Domain")
    print("  [5] URL Reputation Check")
    print("  [0] Back\n")

    choice = input("  Select: ").strip()

    if choice == "1":
        domain = input("  Enter brand domain (e.g. example.com): ").strip()
        check_dns = input("  Check DNS registration for each permutation? [y/N]: ").strip().lower() == "y"
        check_typosquats(domain, check_dns)

    elif choice == "2":
        domain = input("  Enter domain: ").strip()
        cert_transparency(domain)

    elif choice == "3":
        brand   = input("  Enter legitimate brand domain: ").strip()
        suspect = input("  Enter suspect domain: ").strip()
        score   = lookalike_score(brand, suspect)
        result("Edit Distance:", str(score["edit_distance"]))
        result("Similarity:", f"{score['similarity_pct']}%")
        result("Verdict:", score["verdict"])
        audit_log.log("LOOKALIKE_SCORE", f"{brand} vs {suspect}")

    elif choice == "4":
        url = input("  Enter URL or domain: ").strip()
        geo_check(url)

    elif choice == "5":
        from modules.reputation_check import single_check
        url = input("  Enter URL: ").strip()
        single_check(url)

    elif choice == "0":
        return
    else:
        warn("Invalid option")
