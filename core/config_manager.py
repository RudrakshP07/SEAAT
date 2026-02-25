"""
SEAAT Config Manager
Handles encrypted storage and retrieval of API keys.
"""

import os
import json

CONFIG_DIR  = os.path.join(os.path.dirname(os.path.dirname(__file__)), "config")
KEY_FILE    = os.path.join(CONFIG_DIR, "seaat.key")
CONFIG_FILE = os.path.join(CONFIG_DIR, "seaat_config.enc")
PLAIN_FILE  = os.path.join(CONFIG_DIR, "seaat_config.json")   # fallback for dev

_api_keys: dict = {}

API_KEY_NAMES = [
    "virustotal",
    "abuseipdb",
    "alienvault_otx",
    "urlscan",
    "apivoid",
    "shodan",
    "greynoise",
    "hybrid_analysis",
]

def _get_fernet():
    try:
        from cryptography.fernet import Fernet
    except ImportError:
        return None

    if not os.path.exists(KEY_FILE):
        return None

    with open(KEY_FILE, "rb") as f:
        key = f.read().strip()
    from cryptography.fernet import Fernet
    return Fernet(key)


def fetch_api_keys():
    """Load API keys into memory. Raises exception if not configured."""
    global _api_keys
    os.makedirs(CONFIG_DIR, exist_ok=True)

    # Try encrypted config
    fernet = _get_fernet()
    if fernet and os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "rb") as f:
            encrypted = f.read()
        decrypted = fernet.decrypt(encrypted)
        _api_keys = json.loads(decrypted.decode())
        return

    # Try plaintext JSON fallback
    if os.path.exists(PLAIN_FILE):
        with open(PLAIN_FILE, "r") as f:
            _api_keys = json.load(f)
        return

    raise FileNotFoundError("No API key configuration found.")


def save_api_keys(keys: dict, use_encryption: bool = True):
    """Save API keys, optionally encrypting them."""
    global _api_keys
    os.makedirs(CONFIG_DIR, exist_ok=True)
    _api_keys = keys

    if use_encryption:
        try:
            from cryptography.fernet import Fernet
            # Generate new key if not exists
            if not os.path.exists(KEY_FILE):
                key = Fernet.generate_key()
                with open(KEY_FILE, "wb") as f:
                    f.write(key)
            fernet = _get_fernet()
            encrypted = fernet.encrypt(json.dumps(keys).encode())
            with open(CONFIG_FILE, "wb") as f:
                f.write(encrypted)
            print("  [+] API keys encrypted and saved.")
            return
        except ImportError:
            print("  [!] cryptography library not found - saving in plaintext fallback.")

    with open(PLAIN_FILE, "w") as f:
        json.dump(keys, f, indent=2)
    print("  [+] API keys saved (plaintext fallback).")


def get_key(name: str) -> str:
    """Return a specific API key or empty string."""
    return _api_keys.get(name, "")


def all_keys() -> dict:
    return dict(_api_keys)
