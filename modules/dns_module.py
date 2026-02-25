"""
SEAAT Module 2 - DNS / WHOIS Lookup
Features: Reverse DNS, DNS Records, WHOIS, ISP, SPF/DKIM/DMARC
"""

import socket
from core.banner import section_header, info, success, warn, error, result
from core import audit_log


def reverse_dns(ip: str):
    info(f"Performing reverse DNS for {ip}...")
    try:
        host = socket.gethostbyaddr(ip)
        result("Hostname:", host[0])
        result("Aliases:", ", ".join(host[1]) if host[1] else "None")
    except socket.herror:
        warn("No reverse DNS record found.")
    except Exception as e:
        error(str(e))


def dns_lookup(domain: str):
    info(f"DNS lookup for: {domain}")
    try:
        import dns.resolver
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]
        for rtype in record_types:
            try:
                answers = dns.resolver.resolve(domain, rtype)
                for rdata in answers:
                    result(f"{rtype} Record:", str(rdata))
            except Exception:
                pass
    except ImportError:
        # Fallback with socket
        try:
            ips = socket.gethostbyname_ex(domain)
            result("A Records:", ", ".join(ips[2]))
        except Exception as e:
            error(str(e))


def email_security_records(domain: str):
    """Check SPF, DKIM (common selectors), DMARC."""
    info(f"Checking email security records for: {domain}")
    try:
        import dns.resolver

        # SPF
        try:
            spf = dns.resolver.resolve(domain, "TXT")
            for r in spf:
                txt = str(r)
                if "v=spf1" in txt:
                    result("SPF Record:", txt[:100])
        except Exception:
            warn("No SPF record found")

        # DMARC
        try:
            dmarc = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
            for r in dmarc:
                result("DMARC Record:", str(r)[:100])
        except Exception:
            warn("No DMARC record found")

        # DKIM (common selectors)
        for selector in ["default", "google", "mail", "k1", "selector1", "selector2"]:
            try:
                dkim = dns.resolver.resolve(f"{selector}._domainkey.{domain}", "TXT")
                for r in dkim:
                    result(f"DKIM ({selector}):", str(r)[:80] + "...")
                    break
            except Exception:
                pass

    except ImportError:
        warn("dnspython not installed. Install with: pip install dnspython")


def whois_lookup(domain: str):
    info(f"WHOIS lookup for: {domain}")
    try:
        import whois
        w = whois.whois(domain)
        fields = {
            "Registrar":        w.registrar,
            "Created Date":     str(w.creation_date)[:30] if w.creation_date else "N/A",
            "Expiry Date":      str(w.expiration_date)[:30] if w.expiration_date else "N/A",
            "Updated Date":     str(w.updated_date)[:30] if w.updated_date else "N/A",
            "Name Servers":     ", ".join(w.name_servers[:3]) if w.name_servers else "N/A",
            "WHOIS Status":     str(w.status)[:60] if w.status else "N/A",
            "Registrant Org":   w.org or "N/A",
            "Registrant Country": w.country or "N/A",
        }
        for k, v in fields.items():
            result(k + ":", str(v))

        # Domain age warning
        if w.creation_date:
            import datetime
            cd = w.creation_date
            if isinstance(cd, list):
                cd = cd[0]
            age_days = (datetime.datetime.now() - cd).days
            if age_days < 30:
                warn(f"Domain is only {age_days} days old - SUSPICIOUS!")
            else:
                result("Domain Age:", f"{age_days} days")

    except ImportError:
        warn("python-whois not installed. Install with: pip install python-whois")
    except Exception as e:
        error(str(e))


def isp_lookup(ip: str):
    info(f"ISP/GeoIP lookup for: {ip}")
    from core import api_helper
    data = api_helper.get(f"https://ipinfo.io/{ip}/json",
                          cache_key=f"ipinfo_{ip}")
    if "_error" in data:
        error(data["_error"])
        return
    for k in ["org", "country", "region", "city", "hostname", "timezone"]:
        if k in data:
            result(k.capitalize() + ":", data[k])


def fast_flux_detect(domain: str):
    """Detect potential fast-flux by checking TTL and number of A records."""
    info(f"Fast-flux detection for: {domain}")
    try:
        import dns.resolver
        answers = dns.resolver.resolve(domain, "A")
        ips = [str(r) for r in answers]
        ttl = answers.rrset.ttl

        result("A Records Found:", str(len(ips)))
        result("TTL (seconds):", str(ttl))

        if len(ips) >= 4:
            warn("Multiple A records detected - possible fast-flux")
        if ttl < 300:
            warn(f"Very low TTL ({ttl}s) - possible fast-flux or CDN")
        if len(ips) < 4 and ttl >= 300:
            success("No fast-flux indicators detected")
    except ImportError:
        warn("dnspython not installed.")
    except Exception as e:
        error(str(e))


def menu():
    section_header("DNS / WHOIS LOOKUP")
    print("  [1] Reverse DNS Lookup")
    print("  [2] DNS Record Lookup (A, MX, NS, TXT, CNAME ...)")
    print("  [3] WHOIS Lookup")
    print("  [4] ISP / GeoIP Lookup")
    print("  [5] SPF / DKIM / DMARC Check")
    print("  [6] Fast-Flux Detection")
    print("  [0] Back\n")

    choice = input("  Select: ").strip()

    if choice == "1":
        ip = input("  Enter IP address: ").strip()
        reverse_dns(ip)
        audit_log.log("REVERSE_DNS", ip)
    elif choice == "2":
        domain = input("  Enter domain: ").strip()
        dns_lookup(domain)
        audit_log.log("DNS_LOOKUP", domain)
    elif choice == "3":
        domain = input("  Enter domain: ").strip()
        whois_lookup(domain)
        audit_log.log("WHOIS_LOOKUP", domain)
    elif choice == "4":
        ip = input("  Enter IP address: ").strip()
        isp_lookup(ip)
        audit_log.log("ISP_LOOKUP", ip)
    elif choice == "5":
        domain = input("  Enter domain: ").strip()
        email_security_records(domain)
        audit_log.log("EMAIL_RECORDS", domain)
    elif choice == "6":
        domain = input("  Enter domain: ").strip()
        fast_flux_detect(domain)
        audit_log.log("FAST_FLUX", domain)
    elif choice == "0":
        return
    else:
        warn("Invalid option")
