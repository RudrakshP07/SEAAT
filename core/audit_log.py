"""
SEAAT Audit Logger
Appends timestamped entries to a session audit log.
"""

import os
import datetime
import json

LOG_DIR  = os.path.join(os.path.dirname(os.path.dirname(__file__)), "reports")
LOG_FILE = os.path.join(LOG_DIR, "audit.log")


def log(action: str, detail: str = ""):
    os.makedirs(LOG_DIR, exist_ok=True)
    entry = {
        "ts": datetime.datetime.now().isoformat(),
        "action": action,
        "detail": detail,
    }
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(entry) + "\n")


def show_recent(n: int = 20):
    if not os.path.exists(LOG_FILE):
        print("  [!] No audit log found.")
        return
    with open(LOG_FILE) as f:
        lines = f.readlines()
    recent = lines[-n:]
    print(f"\n  Last {len(recent)} audit entries:\n")
    for line in recent:
        try:
            e = json.loads(line)
            print(f"  {e['ts']}  [{e['action']}]  {e['detail']}")
        except Exception:
            print(f"  {line.strip()}")
