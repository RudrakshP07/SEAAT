"""
SEAAT Module 6 - IOC Sanitization / Defanging
Features: Defang, Refang, Bulk, File export
"""

import os
import re
from core.banner import section_header, info, success, warn, error, result
from core import audit_log


def defang(ioc: str) -> str:
    """Defang an IOC for safe sharing."""
    safe = ioc
    safe = safe.replace("http://",  "hxxp://")
    safe = safe.replace("https://", "hxxps://")
    safe = re.sub(r"\.", "[.]", safe)
    safe = safe.replace("@", "[@]")
    return safe


def refang(ioc: str) -> str:
    """Refang / restore a defanged IOC."""
    raw = ioc
    raw = raw.replace("hxxp://",  "http://")
    raw = raw.replace("hxxps://", "https://")
    raw = raw.replace("[.]", ".")
    raw = raw.replace("[@]", "@")
    raw = raw.replace("(.", ".")
    raw = raw.replace(".)", ".")
    return raw


def process_text(text: str, mode: str) -> str:
    """Process text and defang/refang all IOCs."""
    lines = text.splitlines()
    out = []
    for line in lines:
        if mode == "defang":
            out.append(defang(line))
        else:
            out.append(refang(line))
    return "\n".join(out)


def menu():
    section_header("IOC SANITIZATION")
    print("  [1] Defang Single IOC")
    print("  [2] Refang (Restore) Single IOC")
    print("  [3] Bulk Defang (paste text)")
    print("  [4] Bulk Refang (paste text)")
    print("  [5] Process File")
    print("  [0] Back\n")

    choice = input("  Select: ").strip()

    if choice == "1":
        ioc = input("  Enter IOC to defang: ").strip()
        d = defang(ioc)
        result("Defanged:", d)
        audit_log.log("DEFANG", ioc)

    elif choice == "2":
        ioc = input("  Enter defanged IOC to restore: ").strip()
        r = refang(ioc)
        result("Refanged:", r)
        audit_log.log("REFANG", ioc)

    elif choice in ("3", "4"):
        mode = "defang" if choice == "3" else "refang"
        print(f"  Paste text to {mode} (end with blank line):")
        lines = []
        while True:
            line = input()
            if line == "":
                break
            lines.append(line)
        if lines:
            out = process_text("\n".join(lines), mode)
            print(f"\n  {'─'*60}")
            print(out)
            print(f"  {'─'*60}")
            save = input("  Save to file? [y/N]: ").strip().lower()
            if save == "y":
                fpath = input("  Output file path: ").strip()
                with open(fpath, "w") as f:
                    f.write(out)
                success(f"Saved to {fpath}")
        audit_log.log("BULK_" + mode.upper(), f"{len(lines)} lines")

    elif choice == "5":
        path = input("  File path: ").strip()
        if not os.path.exists(path):
            error("File not found")
            return
        mode = input("  Mode [defang/refang]: ").strip().lower()
        if mode not in ("defang", "refang"):
            warn("Invalid mode")
            return
        with open(path) as f:
            text = f.read()
        out = process_text(text, mode)
        outpath = path + f".{mode}d.txt"
        with open(outpath, "w") as f:
            f.write(out)
        success(f"Output saved: {outpath}")
        audit_log.log("FILE_" + mode.upper(), path)

    elif choice == "0":
        return
    else:
        warn("Invalid option")
