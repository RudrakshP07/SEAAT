"""
SEAAT Module 11 - Case Manager
Create, manage, and export investigation cases.
SOC-style case tracking with IOC tagging and report generation.
"""

import os
import json
import datetime
from core.banner import section_header, info, success, warn, error, result
from core import audit_log

CASES_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "reports", "cases")
os.makedirs(CASES_DIR, exist_ok=True)


def _case_path(case_id: str) -> str:
    return os.path.join(CASES_DIR, f"{case_id}.json")


def _load_case(case_id: str) -> dict:
    path = _case_path(case_id)
    if not os.path.exists(path):
        return {}
    with open(path) as f:
        return json.load(f)


def _save_case(case: dict):
    with open(_case_path(case["id"]), "w") as f:
        json.dump(case, f, indent=2)


def _new_case_id() -> str:
    ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    return f"CASE-{ts}"


def list_cases():
    """List all existing cases."""
    files = [f for f in os.listdir(CASES_DIR) if f.endswith(".json")]
    if not files:
        warn("No cases found.")
        return []
    print(f"\n  {'ID':<25} {'Title':<35} {'Status':<15} {'IOCs'}")
    print(f"  {'─'*25} {'─'*35} {'─'*15} {'─'*5}")
    for f in sorted(files):
        case = _load_case(f.replace(".json", ""))
        print(f"  {case.get('id','?'):<25} {case.get('title','?')[:33]:<35} "
              f"{case.get('status','?'):<15} {len(case.get('iocs', []))}")
    return files


def create_case():
    """Create a new investigation case."""
    title    = input("  Case title: ").strip()
    analyst  = input("  Analyst name: ").strip()
    severity = input("  Severity [LOW/MEDIUM/HIGH/CRITICAL]: ").strip().upper()
    desc     = input("  Brief description: ").strip()

    case_id = _new_case_id()
    case = {
        "id":          case_id,
        "title":       title,
        "analyst":     analyst,
        "severity":    severity,
        "description": desc,
        "status":      "OPEN",
        "created_at":  datetime.datetime.now().isoformat(),
        "updated_at":  datetime.datetime.now().isoformat(),
        "iocs":        [],
        "notes":       [],
        "timeline":    [],
    }
    _save_case(case)
    success(f"Case created: {case_id}")
    audit_log.log("CASE_CREATE", case_id)
    return case_id


def add_ioc(case_id: str):
    """Add an IOC to a case with verdict tagging."""
    case = _load_case(case_id)
    if not case:
        error(f"Case {case_id} not found")
        return

    ioc     = input("  IOC value: ").strip()
    ioc_type = input("  IOC type [ip/domain/url/hash/email]: ").strip().lower()
    verdict = input("  Verdict [malicious/suspicious/false_positive/under_investigation]: ").strip().lower()
    tags    = input("  Tags (comma separated): ").strip()

    entry = {
        "ioc":       ioc,
        "type":      ioc_type,
        "verdict":   verdict,
        "tags":      [t.strip() for t in tags.split(",") if t.strip()],
        "added_at":  datetime.datetime.now().isoformat(),
    }
    case["iocs"].append(entry)
    case["updated_at"] = datetime.datetime.now().isoformat()
    _save_case(case)
    success(f"IOC added to {case_id}")
    audit_log.log("CASE_ADD_IOC", f"{case_id}:{ioc}")


def add_note(case_id: str):
    """Add analyst note to a case."""
    case = _load_case(case_id)
    if not case:
        error("Case not found")
        return
    note = input("  Note: ").strip()
    case["notes"].append({
        "text":      note,
        "timestamp": datetime.datetime.now().isoformat(),
    })
    case["updated_at"] = datetime.datetime.now().isoformat()
    _save_case(case)
    success("Note added")


def view_case(case_id: str):
    """Display full case details."""
    case = _load_case(case_id)
    if not case:
        error("Case not found")
        return

    try:
        from colorama import Fore, Style
    except ImportError:
        class _D:
            def __getattr__(self, n): return ""
        Fore = Style = _D()

    print(f"\n  {'═'*62}")
    print(f"  {Fore.CYAN}{Style.BRIGHT}CASE: {case['id']}{Style.RESET_ALL}")
    print(f"  {'─'*62}")
    result("Title:",       case.get("title"))
    result("Analyst:",     case.get("analyst"))
    result("Severity:",    case.get("severity"))
    result("Status:",      case.get("status"))
    result("Created:",     case.get("created_at", "")[:19])
    result("Description:", case.get("description"))

    iocs = case.get("iocs", [])
    if iocs:
        print(f"\n  IOCs ({len(iocs)}):")
        for ioc in iocs:
            verdict_color = {
                "malicious":            Fore.RED,
                "suspicious":           Fore.YELLOW,
                "false_positive":       Fore.GREEN,
                "under_investigation":  Fore.CYAN,
            }.get(ioc.get("verdict", ""), Fore.WHITE)
            print(f"    {verdict_color}[{ioc.get('verdict','?').upper():<22}]{Style.RESET_ALL} "
                  f"{ioc.get('type','?'):<8} {ioc.get('ioc','?')}")

    notes = case.get("notes", [])
    if notes:
        print(f"\n  Notes ({len(notes)}):")
        for n in notes:
            print(f"    [{n['timestamp'][:19]}] {n['text']}")

    print(f"  {'═'*62}\n")


def export_case(case_id: str):
    """Export case as JSON or Markdown report."""
    case = _load_case(case_id)
    if not case:
        error("Case not found")
        return

    fmt = input("  Export format [json/markdown]: ").strip().lower()
    outpath = input("  Output file path: ").strip()

    if fmt == "json":
        with open(outpath, "w") as f:
            json.dump(case, f, indent=2)
        success(f"Case exported as JSON: {outpath}")

    elif fmt == "markdown":
        lines = [
            f"# SEAAT Case Report: {case['id']}",
            f"\n**Title:** {case.get('title')}",
            f"**Analyst:** {case.get('analyst')}",
            f"**Severity:** {case.get('severity')}",
            f"**Status:** {case.get('status')}",
            f"**Created:** {case.get('created_at', '')[:19]}",
            f"\n## Description\n{case.get('description')}",
            f"\n## IOCs ({len(case.get('iocs', []))})\n",
            "| IOC | Type | Verdict | Tags |",
            "|-----|------|---------|------|",
        ]
        for ioc in case.get("iocs", []):
            tags = ", ".join(ioc.get("tags", []))
            lines.append(f"| {ioc.get('ioc')} | {ioc.get('type')} | {ioc.get('verdict')} | {tags} |")

        if case.get("notes"):
            lines.append(f"\n## Analyst Notes\n")
            for n in case["notes"]:
                lines.append(f"- `{n['timestamp'][:19]}` {n['text']}")

        lines.append(f"\n---\n*Generated by SEAAT v2.0*")

        with open(outpath, "w") as f:
            f.write("\n".join(lines))
        success(f"Case exported as Markdown: {outpath}")

    else:
        warn("Unknown format")

    audit_log.log("CASE_EXPORT", f"{case_id} -> {outpath}")


def handover_report():
    """Generate a shift handover summary of all open cases."""
    files = [f for f in os.listdir(CASES_DIR) if f.endswith(".json")]
    open_cases = []
    for f in files:
        case = _load_case(f.replace(".json", ""))
        if case.get("status") == "OPEN":
            open_cases.append(case)

    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    lines = [
        f"# SEAAT Shift Handover Report",
        f"**Generated:** {now}",
        f"**Open Cases:** {len(open_cases)}",
        "",
        "## Open Cases Summary",
    ]
    for case in open_cases:
        lines.append(f"\n### {case['id']} - {case['title']}")
        lines.append(f"- **Severity:** {case.get('severity')}")
        lines.append(f"- **Analyst:** {case.get('analyst')}")
        lines.append(f"- **IOCs:** {len(case.get('iocs', []))}")
        lines.append(f"- **Description:** {case.get('description')}")

    outpath = os.path.join(CASES_DIR, f"handover_{datetime.datetime.now().strftime('%Y%m%d_%H%M')}.md")
    with open(outpath, "w") as f:
        f.write("\n".join(lines))
    success(f"Handover report saved: {outpath}")
    print("\n".join(lines[:40]))


def menu():
    section_header("CASE MANAGER")
    print("  [1] List All Cases")
    print("  [2] Create New Case")
    print("  [3] View Case")
    print("  [4] Add IOC to Case")
    print("  [5] Add Note to Case")
    print("  [6] Export Case (JSON / Markdown)")
    print("  [7] Generate Shift Handover Report")
    print("  [0] Back\n")

    choice = input("  Select: ").strip()

    if choice == "1":
        list_cases()
    elif choice == "2":
        create_case()
    elif choice == "3":
        case_id = input("  Case ID: ").strip()
        view_case(case_id)
    elif choice == "4":
        case_id = input("  Case ID: ").strip()
        add_ioc(case_id)
    elif choice == "5":
        case_id = input("  Case ID: ").strip()
        add_note(case_id)
    elif choice == "6":
        case_id = input("  Case ID: ").strip()
        export_case(case_id)
    elif choice == "7":
        handover_report()
    elif choice == "0":
        return
    else:
        warn("Invalid option")
