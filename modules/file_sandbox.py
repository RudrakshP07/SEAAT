"""
SEAAT Module 5 - File Sandbox & Static Analysis
Features: Hash computation, VT lookup, MalwareBazaar, PE analysis,
          String extraction, Macro detection (oletools), PDF analysis
"""

import os
import hashlib
from core.banner import section_header, info, success, warn, error, result
from core import api_helper, config_manager, audit_log


def compute_hashes(filepath: str) -> dict:
    """Compute MD5, SHA1, SHA256 of a file."""
    hashes = {}
    try:
        with open(filepath, "rb") as f:
            data = f.read()
        hashes["md5"]    = hashlib.md5(data).hexdigest()
        hashes["sha1"]   = hashlib.sha1(data).hexdigest()
        hashes["sha256"] = hashlib.sha256(data).hexdigest()
        hashes["size"]   = len(data)
        hashes["_data"]  = data
    except Exception as e:
        hashes["_error"] = str(e)
    return hashes


def detect_filetype(data: bytes) -> str:
    """Detect file type from magic bytes."""
    signatures = {
        b"\x4d\x5a":         "Windows PE/EXE",
        b"\x7fELF":           "ELF Binary (Linux)",
        b"PK\x03\x04":        "ZIP Archive",
        b"\xd0\xcf\x11\xe0":  "Microsoft OLE (doc/xls/ppt)",
        b"%PDF":               "PDF Document",
        b"\x25\x50\x44\x46":  "PDF Document",
        b"MZ":                 "DOS/PE Executable",
        b"\x1f\x8b":          "GZIP Archive",
        b"Rar!":               "RAR Archive",
        b"\x42\x5a\x68":      "BZIP2 Archive",
        b"\x89PNG":            "PNG Image",
        b"\xff\xd8\xff":       "JPEG Image",
    }
    for magic, name in signatures.items():
        if data[:len(magic)] == magic or data[:4].startswith(magic[:4]):
            return name
    return "Unknown"


def vt_file_check(sha256: str) -> dict:
    key = config_manager.get_key("virustotal")
    if not key:
        return {"_error": "VirusTotal API key not configured"}
    headers = {"x-apikey": key}
    data = api_helper.get(f"https://www.virustotal.com/api/v3/files/{sha256}",
                          headers=headers, cache_key=f"vt_file_{sha256}")
    if "_error" in data:
        return data
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    return {
        "malicious":  stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless":   stats.get("harmless", 0),
        "name":       attrs.get("meaningful_name", "N/A"),
        "type":       attrs.get("type_description", "N/A"),
        "tags":       ", ".join(attrs.get("tags", [])[:5]),
    }


def malwarebazaar_check(sha256: str) -> dict:
    data = api_helper.post(
        "https://mb-api.abuse.ch/api/v1/",
        data={"query": "get_info", "hash": sha256}
    )
    if "_error" in data:
        return data
    if data.get("query_status") == "hash_not_found":
        return {"found": False}
    items = data.get("data", [{}])
    if items:
        d = items[0]
        return {
            "found":       True,
            "file_name":   d.get("file_name", "N/A"),
            "file_type":   d.get("file_type", "N/A"),
            "signature":   d.get("signature", "N/A"),
            "tags":        ", ".join(d.get("tags", [])[:5]) if d.get("tags") else "None",
            "first_seen":  d.get("first_seen", "N/A"),
        }
    return {"found": False}


def extract_strings(data: bytes, min_len: int = 6) -> list:
    """Extract printable ASCII strings from binary data."""
    import re
    strings = re.findall(rb"[ -~]{" + str(min_len).encode() + rb",}", data)
    return [s.decode(errors="replace") for s in strings[:100]]


def pe_analysis(data: bytes) -> dict:
    """Basic PE header analysis."""
    try:
        import pefile
        pe = pefile.PE(data=data)
        imports = []
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll = entry.dll.decode(errors="replace")
                imports.append(dll)
        sections = [s.Name.decode(errors="replace").strip("\x00")
                    for s in pe.sections]
        return {
            "imports": imports[:10],
            "sections": sections,
            "is_dll": pe.is_dll(),
            "is_exe": pe.is_exe(),
            "machine_type": hex(pe.FILE_HEADER.Machine),
        }
    except ImportError:
        return {"_error": "pefile not installed"}
    except Exception as e:
        return {"_error": str(e)}


def macro_check(filepath: str) -> dict:
    """Check Office documents for macros using oletools."""
    try:
        from oletools.olevba import VBA_Parser
        vba = VBA_Parser(filepath)
        if vba.detect_vba_macros():
            macros = []
            for (filename, stream_path, vba_filename, vba_code) in vba.extract_macros():
                macros.append({
                    "stream": stream_path,
                    "code_snippet": vba_code[:200],
                })
            return {"has_macros": True, "count": len(macros), "macros": macros}
        return {"has_macros": False}
    except ImportError:
        return {"_error": "oletools not installed. pip install oletools"}
    except Exception as e:
        return {"_error": str(e)}


def pdf_analysis(filepath: str) -> dict:
    """Check PDF for embedded scripts, URIs, and actions."""
    try:
        import pdfminer
        from pdfminer.high_level import extract_text
        text = extract_text(filepath)
        urls = []
        import re
        urls = re.findall(r"https?://[^\s\"'>]+", text)
        return {"extracted_urls": urls[:20], "text_length": len(text)}
    except ImportError:
        # Try pdfid if available
        return {"_error": "pdfminer not installed. pip install pdfminer.six"}
    except Exception as e:
        return {"_error": str(e)}


def analyze_file(filepath: str):
    if not os.path.exists(filepath):
        error(f"File not found: {filepath}")
        return

    info(f"Analyzing: {filepath}")
    filename = os.path.basename(filepath)
    ext = os.path.splitext(filename)[1].lower()

    hashes = compute_hashes(filepath)
    if "_error" in hashes:
        error(hashes["_error"])
        return

    data = hashes.pop("_data")

    print(f"\n  {'─'*60}")
    result("File Name:", filename)
    result("File Size:", f"{hashes['size']:,} bytes")
    result("File Type:", detect_filetype(data))
    result("MD5:",    hashes["md5"])
    result("SHA1:",   hashes["sha1"])
    result("SHA256:", hashes["sha256"])

    # VT Check
    info("Querying VirusTotal...")
    vt = vt_file_check(hashes["sha256"])
    if "_error" not in vt:
        result("VT Malicious:", str(vt.get("malicious")))
        result("VT Suspicious:", str(vt.get("suspicious")))
        result("VT File Type:", str(vt.get("type")))
        result("VT Tags:", str(vt.get("tags")))
    else:
        warn(f"VT: {vt['_error']}")

    # MalwareBazaar
    info("Querying MalwareBazaar...")
    mb = malwarebazaar_check(hashes["sha256"])
    if mb.get("found"):
        success("FOUND in MalwareBazaar!")
        result("Signature:", mb.get("signature"))
        result("File Type:", mb.get("file_type"))
        result("Tags:", mb.get("tags"))
        result("First Seen:", mb.get("first_seen"))
    elif "_error" not in mb:
        success("Not found in MalwareBazaar")

    # PE analysis
    if ext in (".exe", ".dll", ".sys", ".com") or data[:2] == b"MZ":
        info("Performing PE header analysis...")
        pe = pe_analysis(data)
        if "_error" not in pe:
            result("Is EXE:", str(pe.get("is_exe")))
            result("Is DLL:", str(pe.get("is_dll")))
            result("Machine:", pe.get("machine_type"))
            result("Sections:", ", ".join(pe.get("sections", [])))
            result("DLL Imports:", ", ".join(pe.get("imports", []))[:80])

    # Macro analysis
    if ext in (".doc", ".docm", ".xls", ".xlsm", ".ppt", ".pptm"):
        info("Checking for VBA macros...")
        mc = macro_check(filepath)
        if "_error" not in mc:
            if mc.get("has_macros"):
                warn(f"MACROS FOUND: {mc['count']} macro stream(s)")
            else:
                success("No macros detected")
        else:
            warn(mc["_error"])

    # PDF analysis
    if ext == ".pdf":
        info("Analyzing PDF structure...")
        pdf = pdf_analysis(filepath)
        if "_error" not in pdf:
            if pdf.get("extracted_urls"):
                warn(f"URLs found in PDF: {len(pdf['extracted_urls'])}")
                for u in pdf["extracted_urls"][:5]:
                    print(f"    {u}")

    # String extraction
    do_strings = input("\n  Extract readable strings? [y/N]: ").strip().lower()
    if do_strings == "y":
        info("Extracting strings...")
        strings = extract_strings(data)
        sus_keywords = ["http", "cmd", "powershell", "exec", "eval", "base64",
                        "CreateProcess", "WScript", "regsvr32", "rundll"]
        sus_strings = [s for s in strings if any(k.lower() in s.lower() for k in sus_keywords)]
        if sus_strings:
            warn(f"Suspicious strings ({len(sus_strings)}):")
            for s in sus_strings[:15]:
                print(f"    {s[:100]}")
        else:
            info(f"Extracted {len(strings)} strings - no obvious suspicious patterns")

    print(f"  {'─'*60}")
    audit_log.log("FILE_ANALYSIS", f"{filename} sha256={hashes['sha256'][:16]}...")


def menu():
    section_header("FILE SANDBOX & STATIC ANALYSIS")
    print("  [1] Analyze a File")
    print("  [2] Hash Lookup Only (no file needed)")
    print("  [0] Back\n")

    choice = input("  Select: ").strip()
    if choice == "1":
        path = input("  Enter file path: ").strip()
        analyze_file(path)
    elif choice == "2":
        h = input("  Enter hash (MD5/SHA1/SHA256): ").strip()
        vt = vt_file_check(h)
        mb = malwarebazaar_check(h) if len(h) == 64 else {}
        if "_error" not in vt:
            result("VT Malicious:", str(vt.get("malicious")))
            result("VT Tags:", str(vt.get("tags")))
        if mb.get("found"):
            success("Found in MalwareBazaar!")
            result("Signature:", mb.get("signature"))
        audit_log.log("HASH_LOOKUP", h)
    elif choice == "0":
        return
    else:
        warn("Invalid option")
