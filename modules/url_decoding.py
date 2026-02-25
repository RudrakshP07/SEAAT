"""
SEAAT Module 4 - URL Decoding & Investigation
Features: URL decode, Base64, SafeLink, ProofPoint, Mimecast, Unshorten, Redirect Chain
"""

import re
import base64
import urllib.parse
from core.banner import section_header, info, success, warn, error, result
from core import api_helper, audit_log


def url_decode(encoded: str):
    """Standard URL / percent decode."""
    info("URL decoding...")
    decoded = urllib.parse.unquote(encoded)
    result("Original:", encoded[:120])
    result("Decoded:", decoded[:120])
    return decoded


def base64_decode(encoded: str):
    """Base64 / Base64URL decode."""
    info("Base64 decoding...")
    # Add padding
    padded = encoded + "=" * (4 - len(encoded) % 4)
    try:
        decoded = base64.urlsafe_b64decode(padded).decode(errors="replace")
        result("Decoded:", decoded[:200])
        return decoded
    except Exception as e:
        error(f"Decode failed: {e}")
        return None


def safelink_decode(url: str) -> str:
    """Decode Microsoft Office 365 SafeLink URLs."""
    info("Decoding O365 SafeLink...")
    # Pattern: https://...safelinks.protection.outlook.com/?url=<encoded>&...
    match = re.search(r"[?&]url=([^&]+)", url)
    if match:
        raw = match.group(1)
        decoded = urllib.parse.unquote(raw)
        result("Original SafeLink:", url[:100])
        result("Decoded URL:", decoded[:200])
        audit_log.log("SAFELINK_DECODE", decoded[:100])
        return decoded
    else:
        warn("Could not find encoded URL parameter in SafeLink")
        return url


def proofpoint_decode(url: str) -> str:
    """Decode ProofPoint URL Defense."""
    info("Decoding ProofPoint URL Defense...")
    # Format: https://urldefense.proofpoint.com/v2/url?u=<encoded>&...
    # or v3 format
    match_v3 = re.search(r"urldefense\.com/v3/__(.+?)__;", url)
    if match_v3:
        encoded = match_v3.group(1).replace("*", "=")
        try:
            decoded = base64.urlsafe_b64decode(encoded + "==").decode(errors="replace")
            result("Decoded URL:", decoded[:200])
            return decoded
        except Exception:
            pass

    match_v2 = re.search(r"[?&]u=([^&]+)", url)
    if match_v2:
        raw = match_v2.group(1).replace("-", "%").replace("_", "/")
        decoded = urllib.parse.unquote(raw)
        result("Decoded URL:", decoded[:200])
        return decoded

    warn("Could not decode ProofPoint URL")
    return url


def mimecast_decode(url: str) -> str:
    """Decode Mimecast URL Protect."""
    info("Decoding Mimecast URL...")
    match = re.search(r"[?&]url=([^&]+)", url)
    if match:
        decoded = urllib.parse.unquote(match.group(1))
        result("Decoded URL:", decoded[:200])
        return decoded
    warn("Could not find URL parameter in Mimecast link")
    return url


def unshorten_url(short_url: str):
    """Follow redirects to get the final destination URL."""
    info(f"Unshortening: {short_url}")
    try:
        import requests
        resp = requests.head(short_url, allow_redirects=True, timeout=10)
        result("Final URL:", resp.url)
        result("Status:", str(resp.status_code))
        audit_log.log("UNSHORTEN", f"{short_url} -> {resp.url}")
        return resp.url
    except ImportError:
        warn("requests library not installed")
    except Exception as e:
        error(str(e))
    return short_url


def redirect_chain(url: str):
    """Trace and display the full redirect chain."""
    info(f"Tracing redirect chain for: {url}")
    try:
        import requests
        session = requests.Session()
        resp = session.get(url, timeout=15, stream=True)
        history = resp.history + [resp]

        print(f"\n  Redirect Chain ({len(history)} hop(s)):\n")
        for i, r in enumerate(history):
            status = r.status_code
            loc    = r.url
            try:
                from colorama import Fore, Style
                if status in (301, 302, 303, 307, 308):
                    color = Fore.YELLOW
                elif status == 200:
                    color = Fore.GREEN
                else:
                    color = Fore.RED
            except ImportError:
                color = ""
            print(f"    {i+1:>2}. [{status}] {loc[:100]}")

        final = history[-1].url
        result("Final Destination:", final[:120])
        audit_log.log("REDIRECT_CHAIN", f"{url} -> {final}")
    except ImportError:
        warn("requests not installed")
    except Exception as e:
        error(str(e))


def extract_iocs_from_url(url: str):
    """Extract embedded domains, IPs, and parameters from a URL."""
    info("Extracting IOCs from URL structure...")
    parsed = urllib.parse.urlparse(url)
    result("Scheme:", parsed.scheme)
    result("Domain:", parsed.netloc)
    result("Path:", parsed.path[:100])

    params = urllib.parse.parse_qs(parsed.query)
    if params:
        print("\n  URL Parameters:")
        for k, v in params.items():
            print(f"    {k} = {', '.join(v)[:80]}")

    # Find embedded IPs
    ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", url)
    if ips:
        result("Embedded IPs:", ", ".join(set(ips)))

    # Find embedded domains in parameters
    domains = re.findall(r"(?:https?://)?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", url)
    unique_domains = list(set(d for d in domains if "." in d and len(d) > 4))
    if unique_domains:
        result("Domains found:", ", ".join(unique_domains[:5]))


def auto_detect_decode(url: str):
    """Auto-detect and decode a URL based on its pattern."""
    info("Auto-detecting URL type...")
    if "safelinks.protection.outlook.com" in url:
        return safelink_decode(url)
    if "urldefense.proofpoint.com" in url:
        return proofpoint_decode(url)
    if "mimecast.com" in url:
        return mimecast_decode(url)
    if re.match(r"https?://(bit\.ly|t\.co|tinyurl|ow\.ly|goo\.gl)", url):
        return unshorten_url(url)
    # Try as Base64 if no slashes
    if "/" not in url and len(url) > 20:
        return base64_decode(url)
    return url_decode(url)


def menu():
    section_header("URL DECODING & INVESTIGATION")
    print("  [1] Auto-Detect & Decode URL")
    print("  [2] Standard URL Decode (percent-encoding)")
    print("  [3] Base64 / Base64URL Decode")
    print("  [4] O365 SafeLink Decoder")
    print("  [5] ProofPoint URL Defense Decoder")
    print("  [6] Mimecast URL Protect Decoder")
    print("  [7] Unshorten URL")
    print("  [8] Full Redirect Chain Trace")
    print("  [9] Extract IOCs from URL Structure")
    print("  [0] Back\n")

    choice = input("  Select: ").strip()
    url_handlers = {
        "1": ("Enter URL to auto-detect & decode: ", auto_detect_decode),
        "2": ("Enter URL-encoded string: ", url_decode),
        "3": ("Enter Base64 string: ", base64_decode),
        "4": ("Enter SafeLink URL: ", safelink_decode),
        "5": ("Enter ProofPoint URL: ", proofpoint_decode),
        "6": ("Enter Mimecast URL: ", mimecast_decode),
        "7": ("Enter short URL: ", unshorten_url),
        "8": ("Enter URL to trace: ", redirect_chain),
        "9": ("Enter URL to extract from: ", extract_iocs_from_url),
    }

    if choice in url_handlers:
        prompt, func = url_handlers[choice]
        url = input(f"  {prompt}").strip()
        if url:
            func(url)
    elif choice == "0":
        return
    else:
        warn("Invalid option")
