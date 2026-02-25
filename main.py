#!/usr/bin/env python3
"""
SEAAT - Security Event Analysis Automation Tool
Main entry point
"""

import time
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core import config_manager
from core.banner import print_banner, print_menu
from core.router import route


def main():
    print_banner()
    time.sleep(0.5)

    # Ensure config/API keys are loaded
    while True:
        try:
            config_manager.fetch_api_keys()
        except Exception:
            print("\n[!] API keys not configured or encryption key missing.")
            print("[!] Redirecting to Configuration Menu...\n")
            from modules import config_module
            config_module.menu()
            try:
                config_manager.fetch_api_keys()
            except Exception:
                print("[!] Configuration failed. Please restart the tool.")
                sys.exit(1)

        print_menu()

        try:
            choice = input("\n[SEAAT]> Select Option: ").strip().lower()

            # Handle Configuration Menu
            if choice == "c":
                from modules import config_module
                config_module.menu()
                continue

            # Handle numeric input
            if not choice.isdigit():
                print("[-] Please enter a valid numeric option (0-12) or C for Configuration.")
                continue

            choice = int(choice)
            if 0 <= choice <= 12:
                route(choice)
            else:
                print("[-] Invalid option. Please select between 0 and 12 or C for Configuration.")

        except KeyboardInterrupt:
            print("\n\n[!] Keyboard interrupt detected.")
            print("[*] Exiting SEAAT. Stay safe!\n")
            sys.exit(0)
        except Exception as e:
            print(f"[-] Unexpected error: {e}")


if __name__ == "__main__":
    main()