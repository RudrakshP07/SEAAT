"""
SEAAT Core Router
Dispatches menu selections to the appropriate module.
"""


def route(choice: int):
    if choice == 0:
        import sys
        from core.banner import info
        info("Exiting SEAAT. Stay safe!\n")
        sys.exit(0)

    elif choice == 1:
        from modules import reputation_check
        reputation_check.menu()

    elif choice == 2:
        from modules import dns_module
        dns_module.menu()

    elif choice == 3:
        from modules import phishing_analysis
        phishing_analysis.menu()

    elif choice == 4:
        from modules import url_decoding
        url_decoding.menu()

    elif choice == 5:
        from modules import file_sandbox
        file_sandbox.menu()

    elif choice == 6:
        from modules import sanitize
        sanitize.menu()

    elif choice == 7:
        from modules import brand_monitor
        brand_monitor.menu()

    elif choice == 8:
        from modules import ioc_extractor
        ioc_extractor.menu()

    elif choice == 9:
        from modules import threat_intel
        threat_intel.menu()

    elif choice == 10:
        from modules import network_analysis
        network_analysis.menu()

    elif choice == 11:
        from modules import case_manager
        case_manager.menu()

    elif choice == 12:
        from modules import soar_toolbox
        soar_toolbox.menu()

    else:
        from modules import config_module
        config_module.menu()
