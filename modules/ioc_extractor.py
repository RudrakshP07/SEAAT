"""
SEAAT Module 8 - IOC Extractor
Extract IPs, domains, URLs, hashes, emails, CVEs from raw text / files
Also handles defanged IOCs (auto-refangs before validation).
"""

import re
import os
from core.banner import section_header, info, success, warn, error, result
from core import audit_log
from modules.sanitize import refang


# ─── Regex Patterns ────────────────────────────────────────────────────────────

PATTERNS = {
    "ipv4":   re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "ipv6":   re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"),
    "domain": re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"),
    "url":    re.compile(r"https?://[^\s\"'<>]+"),
    "md5":    re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "sha1":   re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "email":  re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b"),
    "cve":    re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE),
}

# Common noise domains to filter out
NOISE_DOMAINS = {
    "example.com", "test.com", "localhost", "google.com",
    "microsoft.com", "apple.com", "amazon.com", "cloudflare.com",
}

# Private/reserved IP ranges to filter
def is_private_ip(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        a, b = int(parts[0]), int(parts[1])
        if a == 10: return True
        if a == 172 and 16 <= b <= 31: return True
        if a == 192 and b == 168: return True
        if a == 127: return True
        if a == 0: return True
    except Exception:
        pass
    return False


def extract_iocs(text: str, filter_noise: bool = True) -> dict:
    """Extract all IOC types from text, including defanged ones."""
    # First refang the text
    refanged_text = refang(text)

    results = {}

    for ioc_type, pattern in PATTERNS.items():
        matches = list(set(pattern.findall(refanged_text)))

        if ioc_type == "ipv4" and filter_noise:
            matches = [ip for ip in matches if not is_private_ip(ip)]
        if ioc_type == "domain" and filter_noise:
            matches = [d for d in matches
                       if d.lower() not in NOISE_DOMAINS
                       and not d.endswith(".local")
                       and "." in d and len(d) > 4]

        if matches:
            results[ioc_type] = sorted(matches)

    return results


def display_iocs(extracted: dict):
    if not extracted:
        warn("No IOCs found in the provided text.")
        return

    total = sum(len(v) for v in extracted.values())
    success(f"Extracted {total} IOC(s):\n")

    type_labels = {
        "ipv4": "IPv4 Addresses",
        "ipv6": "IPv6 Addresses",
        "domain": "Domains",
        "url": "URLs",
        "md5": "MD5 Hashes",
        "sha1": "SHA1 Hashes",
        "sha256": "SHA256 Hashes",
        "email": "Email Addresses",
        "cve": "CVE IDs",
    }

    for ioc_type, iocs in extracted.items():
        label = type_labels.get(ioc_type, ioc_type.upper())
        print(f"\n  ── {label} ({len(iocs)}) " + "─" * max(0, 40 - len(label)))
        for ioc in iocs[:30]:
            print(f"    • {ioc}")
        if len(iocs) > 30:
            print(f"    ... and {len(iocs) - 30} more")


def save_iocs(extracted: dict, output_path: str):
    """Save extracted IOCs to a file."""
    with open(output_path, "w") as f:
        for ioc_type, iocs in extracted.items():
            f.write(f"# {ioc_type.upper()}\n")
            for ioc in iocs:
                f.write(ioc + "\n")
            f.write("\n")
    success(f"IOCs saved to: {output_path}")


def extract_from_file(filepath: str) -> dict:
    """Extract IOCs from a text file, .eml, or .log."""
    if not os.path.exists(filepath):
        error(f"File not found: {filepath}")
        return {}

    ext = os.path.splitext(filepath)[1].lower()
    info(f"Reading: {filepath}")

    if ext == ".pdf":
        try:
            from pdfminer.high_level import extract_text
            text = extract_text(filepath)
        except ImportError:
            warn("pdfminer not installed. Reading as binary text fallback.")
            with open(filepath, "rb") as f:
                text = f.read().decode(errors="replace")
    else:
        with open(filepath, "r", errors="replace") as f:
            text = f.read()

    info(f"Read {len(text):,} characters")
    return extract_iocs(text)


def menu():
    section_header("IOC EXTRACTOR")
    print("  [1] Extract from pasted text")
    print("  [2] Extract from file (.txt / .eml / .log / .csv)")
    print("  [3] Extract and immediately run reputation checks")
    print("  [0] Back\n")

    choice = input("  Select: ").strip()

    if choice == "1":
        print("  Paste text (end with a blank line):")
        lines = []
        while True:
            line = input()
            if line == "":
                break
            lines.append(line)
        text = "\n".join(lines)
        if text:
            extracted = extract_iocs(text)
            display_iocs(extracted)
            save = input("\n  Save IOCs to file? [y/N]: ").strip().lower()
            if save == "y":
                outpath = input("  Output path: ").strip()
                save_iocs(extracted, outpath)
            audit_log.log("IOC_EXTRACT", f"text input - {sum(len(v) for v in extracted.values())} IOCs")

    elif choice == "2":
        path = input("  File path: ").strip()
        extracted = extract_from_file(path)
        display_iocs(extracted)
        save = input("\n  Save IOCs to file? [y/N]: ").strip().lower()
        if save == "y":
            outpath = input("  Output path: ").strip()
            save_iocs(extracted, outpath)
        audit_log.log("IOC_EXTRACT_FILE", path)

    elif choice == "3":
        path = input("  File path (or press Enter to paste text): ").strip()
        if path:
            extracted = extract_from_file(path)
        else:
            print("  Paste text (end with blank line):")
            lines = []
            while True:
                line = input()
                if not line:
                    break
                lines.append(line)
            extracted = extract_iocs("\n".join(lines))

        display_iocs(extracted)

        if extracted:
            print("\n  Which IOC types to check reputation on?")
            for t in extracted:
                print(f"    [{t}] {len(extracted[t])} items")
            selected = input("  Enter types (comma separated, e.g. ipv4,domain,url): ").strip()
            types = [s.strip() for s in selected.split(",")]

            from modules.reputation_check import single_check
            for t in types:
                if t in extracted:
                    info(f"Checking {t} IOCs...")
                    for ioc in extracted[t][:5]:  # limit to 5 per type
                        single_check(ioc)

    elif choice == "0":
        return
    else:
        warn("Invalid option")
