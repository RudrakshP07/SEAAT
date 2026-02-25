"""
SEAAT Banner and Menu Display
"""

import os
import datetime

try:
    from colorama import Fore, Back, Style, init
    init(autoreset=True)
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False

    class _Dummy:
        def __getattr__(self, name):
            return ""
    Fore = _Dummy()
    Back = _Dummy()
    Style = _Dummy()


BANNER = r"""
  ██████╗ ███████╗ █████╗  █████╗ ████████╗
 ██╔════╝ ██╔════╝██╔══██╗██╔══██╗╚══██╔══╝
 ╚█████╗  █████╗  ███████║███████║   ██║
  ╚═══██╗ ██╔══╝  ██╔══██║██╔══██║   ██║
 ██████╔╝ ███████╗██║  ██║██║  ██║   ██║
 ╚═════╝  ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝
"""

SUBTITLE = "  Security Event Analysis & Automation Tool"
TAGLINE  = "  SOC Analyst's Unified Threat Investigation Platform"
VERSION  = "  v2.0 | Dept. of CSE - Cyber Security | AITR, Indore"
DIVIDER  = "  " + "═" * 54


def print_banner():
    os.system("clear" if os.name != "nt" else "cls")

    print(Fore.CYAN + Style.BRIGHT + BANNER)
    print(Fore.WHITE + Style.BRIGHT + DIVIDER)
    print(Fore.YELLOW + Style.BRIGHT + SUBTITLE)
    print(Fore.GREEN  + TAGLINE)
    print(Fore.WHITE  + VERSION)
    print(Fore.WHITE  + DIVIDER)

    now = datetime.datetime.now().strftime("%A, %d %B %Y  |  %H:%M:%S")
    print(Fore.CYAN + f"\n  [*] Session started: {now}")
    print(Fore.WHITE + "")


MENU_ITEMS = [
    ("1",  "Reputation / Blocklist Check",       "IPs · Domains · URLs · Hashes"),
    ("2",  "DNS / WHOIS Lookup",                 "Reverse DNS · Records · ISP · WHOIS"),
    ("3",  "Email Security & Phishing Analysis", "Headers · Verify · Temp-Mail · BEC"),
    ("4",  "URL Decoding & Investigation",       "Base64 · SafeLink · Unshorten · Chains"),
    ("5",  "File Sandbox & Static Analysis",     "Hash · Macros · PE · YARA · Strings"),
    ("6",  "IOC Sanitization",                   "Defang · Refang · Bulk · Export"),
    ("7",  "Brand Monitoring & Analysis",        "Typosquat · CertTransparency · Lookalike"),
    ("8",  "IOC Extractor",                      "Extract from text / EML / log / PDF"),
    ("9",  "Threat Intelligence Correlation",    "OTX · ThreatFox · MITRE ATT&CK"),
    ("10", "Network Analysis & Pivot",           "ASN · Infra Map · Shodan · GreyNoise"),
    ("11", "Case Manager",                       "Create · Tag · Export · Handover Report"),
    ("12", "SIEM / SOAR Toolbox",               "Sigma · Splunk · Firewall Rules · Playbooks"),
    ("8*", "Help & Configuration",               "API Keys · Cache · Audit Log"),
    ("0",  "Exit",                               ""),
]


def print_menu():
    print(Fore.WHITE + Style.BRIGHT + "\n  ┌─────────────────────────────────────────────────────────┐")
    print(Fore.WHITE + Style.BRIGHT +   "  │              MAIN INVESTIGATION MENU                   │")
    print(Fore.WHITE + Style.BRIGHT +   "  └─────────────────────────────────────────────────────────┘\n")

    groups = [
        ("THREAT INTELLIGENCE",  ["1","2","9","10"]),
        ("EMAIL & PHISHING",     ["3","4"]),
        ("FILE ANALYSIS",        ["5"]),
        ("IOC MANAGEMENT",       ["6","8"]),
        ("BRAND & MONITORING",   ["7"]),
        ("CASE & RESPONSE",      ["11","12"]),
        ("SYSTEM",               ["8*","0"]),
    ]

    menu_map = {item[0]: item for item in MENU_ITEMS}

    for group_name, keys in groups:
        print(Fore.CYAN + Style.BRIGHT + f"  ── {group_name} " + "─" * max(0, 42 - len(group_name)))
        for k in keys:
            if k not in menu_map:
                continue
            num, title, desc = menu_map[k]
            display_num = num if num != "8*" else "C"  # C for config
            num_str = f"[{display_num:>2}]"
            if k == "0":
                color = Fore.RED
            elif k == "8*":
                color = Fore.MAGENTA
            else:
                color = Fore.GREEN
            print(color + f"  {num_str} " + Fore.WHITE + Style.BRIGHT + f"{title:<38}" +
                  Fore.WHITE + Style.NORMAL + f"  {desc}")
        print()


def section_header(title: str):
    """Print a section header inside a module."""
    width = 60
    bar = "═" * width
    pad = (width - len(title) - 2) // 2
    print(Fore.CYAN + Style.BRIGHT + f"\n  ╔{bar}╗")
    print(Fore.CYAN + Style.BRIGHT + f"  ║{' ' * pad} {title} {' ' * (width - pad - len(title) - 2)}║")
    print(Fore.CYAN + Style.BRIGHT + f"  ╚{bar}╝\n")


def success(msg): print(Fore.GREEN  + Style.BRIGHT + f"  [+] {msg}" + Style.RESET_ALL)
def info(msg):    print(Fore.CYAN   +                f"  [*] {msg}" + Style.RESET_ALL)
def warn(msg):    print(Fore.YELLOW +                f"  [!] {msg}" + Style.RESET_ALL)
def error(msg):   print(Fore.RED    + Style.BRIGHT + f"  [-] {msg}" + Style.RESET_ALL)
def result(k, v): print(Fore.WHITE  + Style.BRIGHT + f"      {k:<28}" + Fore.YELLOW + f"{v}" + Style.RESET_ALL)
