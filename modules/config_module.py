"""
SEAAT Config Module - API Key configuration and system settings
"""

from core.banner import section_header, info, success, warn, error, result
from core import config_manager, audit_log


API_KEY_DESCRIPTIONS = {
    "virustotal":      "VirusTotal (https://www.virustotal.com/gui/my-apikey)",
    "abuseipdb":       "AbuseIPDB  (https://www.abuseipdb.com/account/api)",
    "alienvault_otx":  "AlienVault OTX (https://otx.alienvault.com/api)",
    "urlscan":         "URLScan.io (https://urlscan.io/user/profile/)",
    "apivoid":         "APIVoid    (https://www.apivoid.com/api/)",
    "shodan":          "Shodan     (https://account.shodan.io/) [optional]",
    "greynoise":       "GreyNoise  (https://viz.greynoise.io/) [optional]",
    "hybrid_analysis": "HybridAnalysis (https://www.hybrid-analysis.com/apikeys/new) [optional]",
}


def configure_keys():
    """Interactive API key configuration."""
    section_header("API KEY CONFIGURATION")
    info("Enter API keys (press Enter to skip optional keys)")
    print("  Leave blank to keep existing value.\n")

    existing = {}
    try:
        config_manager.fetch_api_keys()
        existing = config_manager.all_keys()
    except Exception:
        pass

    new_keys = dict(existing)

    for key_name, description in API_KEY_DESCRIPTIONS.items():
        current = existing.get(key_name, "")
        masked  = f"{'*' * (len(current) - 4)}{current[-4:]}" if len(current) > 4 else "not set"
        val = input(f"  {description}\n  Current: [{masked}]  New value: ").strip()
        if val:
            new_keys[key_name] = val
        elif current:
            new_keys[key_name] = current

    use_enc = input("\n  Use encryption for API keys? [Y/n]: ").strip().lower() != "n"
    config_manager.save_api_keys(new_keys, use_encryption=use_enc)
    success("Configuration saved!")
    audit_log.log("CONFIG_SAVE", "API keys updated")


def show_audit_log():
    """Display recent audit log entries."""
    section_header("AUDIT LOG")
    audit_log.show_recent(30)


def show_help():
    """Display help information."""
    try:
        from colorama import Fore, Style
    except ImportError:
        class _D:
            def __getattr__(self, n): return ""
        Fore = Style = _D()

    print(Fore.CYAN + Style.BRIGHT + """
  ╔══════════════════════════════════════════════════════════╗
  ║                    SEAAT v2.0 HELP                       ║
  ╠══════════════════════════════════════════════════════════╣
  ║                                                          ║
  ║  SEAAT (Security Event Analysis Automation Tool)         ║
  ║  is a unified CLI platform for SOC analysts to:          ║
  ║                                                          ║
  ║  • Validate IOCs (IPs, domains, URLs, hashes)            ║
  ║  • Analyze phishing emails and headers                   ║
  ║  • Check email reputation and detect temp-mail           ║
  ║  • Decode obfuscated and shortened URLs                  ║
  ║  • Perform static file analysis                          ║
  ║  • Correlate with MITRE ATT&CK                           ║
  ║  • Generate SIEM hunt queries and Sigma rules            ║
  ║  • Manage investigation cases                            ║
  ║  • Monitor brand impersonation                           ║
  ║                                                          ║
  ║  REQUIRED APIs:                                          ║
  ║    VirusTotal, AbuseIPDB, AlienVault OTX                 ║
  ║                                                          ║
  ║  OPTIONAL APIs:                                          ║
  ║    URLScan, APIVoid, Shodan, GreyNoise                   ║
  ║                                                          ║
  ║  Several features work without any API keys:             ║
  ║    URL decoding, IOC extraction, sanitization,           ║
  ║    SIEM query generation, firewall rule generation,      ║
  ║    MITRE ATT&CK lookup, ThreatFox (free)                 ║
  ║                                                          ║
  ╠══════════════════════════════════════════════════════════╣
  ║  Developed by: Alfiya Khanam · Riya Dubey · Rudra P.     ║
  ║  AITR Indore | CSE - Cyber Security | 2022-2026          ║
  ╚══════════════════════════════════════════════════════════╝
""" + Style.RESET_ALL)


def menu():
    section_header("HELP & CONFIGURATION")
    print("  [1] Help & About")
    print("  [2] Configure / Re-configure API Keys")
    print("  [3] View Audit Log")
    print("  [4] Clear Cache")
    print("  [0] Back\n")

    choice = input("  Select: ").strip()

    if choice == "1":
        show_help()
    elif choice == "2":
        configure_keys()
    elif choice == "3":
        show_audit_log()
    elif choice == "4":
        import os, shutil
        cache_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "cache")
        if os.path.exists(cache_dir):
            shutil.rmtree(cache_dir)
            os.makedirs(cache_dir)
            success("Cache cleared.")
        else:
            info("Cache directory is already empty.")
    elif choice == "0":
        return
    else:
        warn("Invalid option")
