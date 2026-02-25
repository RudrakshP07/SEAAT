#!/usr/bin/env python3
"""
SEAAT Setup Script
Run this once to install dependencies and prepare the environment.
"""

import os
import sys
import subprocess


def run(cmd):
    print(f"  >> {cmd}")
    result = subprocess.run(cmd, shell=True)
    return result.returncode == 0


def main():
    print("\n" + "═" * 60)
    print("  SEAAT v2.0 - Setup & Installation")
    print("═" * 60 + "\n")

    # Check Python version
    if sys.version_info < (3, 8):
        print("  [!] Python 3.8+ required")
        sys.exit(1)
    print(f"  [+] Python {sys.version_info.major}.{sys.version_info.minor} detected")

    # Install core dependencies
    print("\n  Installing core dependencies...\n")
    core_packages = [
        "requests",
        "cryptography",
        "dnspython",
        "python-whois",
        "colorama",
        "rich",
    ]
    for pkg in core_packages:
        success = run(f"{sys.executable} -m pip install {pkg} --quiet")
        status = "[+]" if success else "[!]"
        print(f"  {status} {pkg}")

    # Optional packages
    print("\n  Optional file analysis packages (for full functionality):")
    print("  Run: pip install pefile oletools pdfminer.six yara-python\n")

    # Create directory structure
    dirs = [
        "config",
        "data/cache",
        "reports/cases",
        "plugins",
    ]
    for d in dirs:
        os.makedirs(d, exist_ok=True)
        print(f"  [+] Created: {d}/")

    # Create .gitignore
    gitignore = """# SEAAT - do not commit sensitive files
config/seaat.key
config/seaat_config.enc
config/seaat_config.json
data/cache/
reports/cases/
*.pyc
__pycache__/
.env
"""
    with open(".gitignore", "w") as f:
        f.write(gitignore)
    print("  [+] Created: .gitignore")

    print("\n" + "═" * 60)
    print("  Setup complete! Run: python main.py")
    print("═" * 60 + "\n")


if __name__ == "__main__":
    main()
