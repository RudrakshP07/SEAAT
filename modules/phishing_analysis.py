"""
SEAAT Module 3 - Email Security & Phishing Analysis
Features: Header analysis, Email verification, Temp-mail detection,
          BEC detection, Phishing site analysis, Attachment sandbox
"""

import re
import socket
import os
from core.banner import section_header, info, success, warn, error, result
from core import api_helper, config_manager, audit_log


# ─── Disposable Domain List ───────────────────────────────────────────────────

DISPOSABLE_DOMAINS_URL = "https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/master/disposable_email_blocklist.conf"
DISPOSABLE_CACHE = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                                "data", "disposable_domains.txt")

def load_disposable_domains() -> set:
    """Load known disposable email domains from local cache or remote list."""
    if os.path.exists(DISPOSABLE_CACHE):
        with open(DISPOSABLE_CACHE) as f:
            return set(line.strip().lower() for line in f if line.strip())
    # try to fetch
    try:
        import requests
        resp = requests.get(DISPOSABLE_DOMAINS_URL, timeout=10)
        os.makedirs(os.path.dirname(DISPOSABLE_CACHE), exist_ok=True)
        with open(DISPOSABLE_CACHE, "w") as f:
            f.write(resp.text)
        return set(line.strip().lower() for line in resp.text.splitlines() if line.strip())
    except Exception:
        return set()


# ─── Email Address Verification ───────────────────────────────────────────────

def verify_email(email: str):
    info(f"Verifying email: {email}")

    if not re.match(r"^[^@]+@[^@]+\.[^@]+$", email):
        error("Invalid email format.")
        return

    parts = email.split("@")
    local, domain = parts[0], parts[1].lower()

    # 1. Disposable domain check
    disposable = load_disposable_domains()
    if domain in disposable:
        warn(f"DISPOSABLE EMAIL: '{domain}' is a known temp-mail domain")
    else:
        success("Domain not in known disposable list")

    # 2. DNS / MX record check
    info("Checking MX records...")
    try:
        import dns.resolver
        mx_records = dns.resolver.resolve(domain, "MX")
        mx_list = [str(r.exchange) for r in mx_records]
        result("MX Records:", ", ".join(mx_list[:3]))
        success("Domain accepts email (MX records found)")
    except ImportError:
        warn("dnspython not installed - skipping MX check")
    except Exception:
        warn("No MX records found - domain may not accept email")

    # 3. HTTP probe the domain (temp mail sites often have a web UI)
    info("Probing domain HTTP status...")
    probe = api_helper.head_check(f"https://{domain}")
    if "_error" not in probe:
        result("HTTP Status:", str(probe.get("status_code")))
        result("Server:", probe.get("server", "N/A"))
        result("Final URL:", probe.get("final_url", "N/A"))
    else:
        probe_http = api_helper.head_check(f"http://{domain}")
        if "_error" not in probe_http:
            result("HTTP Status:", str(probe_http.get("status_code")))
        else:
            warn(f"Domain unreachable: {probe['_error']}")

    # 4. APIVoid email verification
    key = config_manager.get_key("apivoid")
    if key:
        info("Querying APIVoid email verification...")
        url  = f"https://endpoint.apivoid.com/emailverify/v1/pay-as-you-go/?key={key}&email={email}"
        data = api_helper.get(url, cache_key=f"apivoid_email_{email}")
        if "_error" not in data:
            report = data.get("data", {}).get("report", {})
            result("Is Disposable:", str(report.get("is_disposable", "?")))
            result("Is Free Provider:", str(report.get("is_free_email", "?")))
            result("Has Valid MX:", str(report.get("has_mx_records", "?")))
            result("Role Address:", str(report.get("is_role_address", "?")))
        else:
            warn(f"APIVoid: {data['_error']}")

    audit_log.log("EMAIL_VERIFY", email)


# ─── Email Header Analysis ────────────────────────────────────────────────────

def analyze_headers(raw_headers: str):
    """Parse raw email headers and extract forensic details."""
    info("Parsing email headers...")

    from_match    = re.search(r"^From:\s*(.+)$", raw_headers, re.MULTILINE | re.IGNORECASE)
    replyto_match = re.search(r"^Reply-To:\s*(.+)$", raw_headers, re.MULTILINE | re.IGNORECASE)
    to_match      = re.search(r"^To:\s*(.+)$", raw_headers, re.MULTILINE | re.IGNORECASE)
    subj_match    = re.search(r"^Subject:\s*(.+)$", raw_headers, re.MULTILINE | re.IGNORECASE)
    date_match    = re.search(r"^Date:\s*(.+)$", raw_headers, re.MULTILINE | re.IGNORECASE)

    print(f"\n  {'─'*60}")
    if from_match:    result("From:",     from_match.group(1).strip())
    if to_match:      result("To:",       to_match.group(1).strip())
    if subj_match:    result("Subject:",  subj_match.group(1).strip())
    if date_match:    result("Date:",     date_match.group(1).strip())
    if replyto_match: result("Reply-To:", replyto_match.group(1).strip())

    # Reply-To vs From mismatch (BEC indicator)
    if from_match and replyto_match:
        from_addr    = from_match.group(1).strip()
        replyto_addr = replyto_match.group(1).strip()
        if from_addr.lower() != replyto_addr.lower():
            warn("REPLY-TO MISMATCH - From and Reply-To differ (BEC indicator!)")

    # SPF/DKIM/DMARC result from headers
    spf_match   = re.search(r"spf=(\w+)", raw_headers, re.IGNORECASE)
    dkim_match  = re.search(r"dkim=(\w+)", raw_headers, re.IGNORECASE)
    dmarc_match = re.search(r"dmarc=(\w+)", raw_headers, re.IGNORECASE)

    print(f"\n  Authentication Results:")
    result("SPF:",   spf_match.group(1).upper()   if spf_match   else "NOT FOUND")
    result("DKIM:",  dkim_match.group(1).upper()  if dkim_match  else "NOT FOUND")
    result("DMARC:", dmarc_match.group(1).upper() if dmarc_match else "NOT FOUND")

    for check, match in [("SPF", spf_match), ("DKIM", dkim_match), ("DMARC", dmarc_match)]:
        if match and match.group(1).lower() == "fail":
            warn(f"{check} FAILED - possible spoofing!")

    # Received hops
    hops = re.findall(r"^Received:.*?(?=^Received:|\Z)", raw_headers,
                      re.MULTILINE | re.DOTALL)
    if hops:
        print(f"\n  Received Hops ({len(hops)} total):")
        for i, hop in enumerate(hops[:5], 1):
            clean = " ".join(hop.split())[:120]
            print(f"    Hop {i}: {clean}")

    # Extract IPs from headers
    ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", raw_headers)
    public_ips = [ip for ip in set(ips) if not ip.startswith(("10.", "192.168.", "127."))]
    if public_ips:
        print(f"\n  Public IPs found in headers: {', '.join(public_ips[:5])}")
        run_rep = input("  Run reputation check on these IPs? [y/N]: ").strip().lower()
        if run_rep == "y":
            from modules.reputation_check import single_check
            for ip in public_ips[:3]:
                single_check(ip)

    # X-Mailer fingerprint
    xmailer = re.search(r"^X-Mailer:\s*(.+)$", raw_headers, re.MULTILINE | re.IGNORECASE)
    if xmailer:
        result("X-Mailer:", xmailer.group(1).strip())

    print(f"  {'─'*60}")
    audit_log.log("HEADER_ANALYSIS", "raw headers parsed")


# ─── BEC Detector ─────────────────────────────────────────────────────────────

BEC_KEYWORDS = [
    "wire transfer", "bank account", "urgent payment", "invoice attached",
    "confidential", "click here", "account details", "immediate action",
    "password reset", "verify your account", "suspended", "unusual activity",
    "gift card", "itunes", "amazon card", "payroll", "ceo", "executive",
]

def bec_detect(text: str):
    """Scan email body/subject for BEC indicators."""
    info("Scanning for BEC (Business Email Compromise) patterns...")
    text_lower = text.lower()
    hits = [kw for kw in BEC_KEYWORDS if kw in text_lower]

    if hits:
        warn(f"BEC INDICATORS FOUND ({len(hits)}):")
        for h in hits:
            print(f"    ⚠  '{h}'")
    else:
        success("No common BEC keywords detected")

    # Urgency patterns
    urgency = re.findall(r"\b(urgent|asap|immediately|today|right now|as soon as possible)\b",
                         text_lower)
    if urgency:
        warn(f"Urgency language detected: {', '.join(set(urgency))}")

    audit_log.log("BEC_DETECT", f"hits={len(hits)}")


# ─── Phishing Site Analysis ───────────────────────────────────────────────────

def analyze_phishing_site(url: str):
    info(f"Analyzing phishing site: {url}")

    # URLScan submission
    key = config_manager.get_key("urlscan")
    if key:
        info("Submitting to URLScan.io...")
        headers = {"API-Key": key, "Content-Type": "application/json"}
        data = api_helper.post("https://urlscan.io/api/v1/scan/",
                               headers=headers,
                               json_body={"url": url, "visibility": "private"})
        if "_error" not in data:
            result("Scan UUID:",   data.get("uuid", "?"))
            result("Result URL:",  data.get("result", "?"))
            result("Screenshot:",  data.get("screenshot", "?"))
        else:
            warn(f"URLScan: {data['_error']}")

    # HTTP probe
    probe = api_helper.head_check(url)
    if "_error" not in probe:
        result("HTTP Status:", str(probe.get("status_code")))
        result("Server:", probe.get("server", "N/A"))

    # VT URL check
    from modules.reputation_check import vt_check
    vt = vt_check(url, "url")
    if "_error" not in vt:
        result("VT Malicious:", str(vt.get("malicious", "?")))
        result("VT Suspicious:", str(vt.get("suspicious", "?")))

    audit_log.log("PHISHING_SITE", url)


# ─── Guidelines ───────────────────────────────────────────────────────────────

def phishing_guidelines():
    from colorama import Fore, Style
    print(Fore.CYAN + Style.BRIGHT + """
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

  4. CONTENT WARNING SIGNS
     • Urgency language ("Act now!", "Account suspended!")
     • Generic greetings ("Dear Customer")
     • Requests for credentials, payments, or gift cards
     • Unexpected attachments (especially .docm, .xlsm, .zip)

  5. ATTACHMENT INDICATORS
     • Macros in Office documents
     • Password-protected ZIPs
     • Double extensions: invoice.pdf.exe

  6. BRAND IMPERSONATION CHECKS
     • Does the sender domain match the brand's official domain?
     • SSL certificate CN match?
     • Similar-looking login page (clone site)
""" + Style.RESET_ALL)


# ─── Menu ─────────────────────────────────────────────────────────────────────

def menu():
    section_header("EMAIL SECURITY & PHISHING ANALYSIS")
    print("  [1] Email Address Verification & Temp-Mail Check")
    print("  [2] Email Header Analysis")
    print("  [3] BEC (Business Email Compromise) Detector")
    print("  [4] Phishing Site Analysis")
    print("  [5] Phishing Identification Guidelines")
    print("  [0] Back\n")

    choice = input("  Select: ").strip()

    if choice == "1":
        email = input("  Enter email address: ").strip()
        verify_email(email)

    elif choice == "2":
        print("  Paste raw email headers (end with a blank line):")
        lines = []
        while True:
            line = input()
            if line == "":
                break
            lines.append(line)
        if lines:
            analyze_headers("\n".join(lines))

    elif choice == "3":
        print("  Paste email body/subject to scan (end with blank line):")
        lines = []
        while True:
            line = input()
            if line == "":
                break
            lines.append(line)
        if lines:
            bec_detect("\n".join(lines))

    elif choice == "4":
        url = input("  Enter phishing site URL: ").strip()
        analyze_phishing_site(url)

    elif choice == "5":
        phishing_guidelines()

    elif choice == "0":
        return
    else:
        warn("Invalid option")
