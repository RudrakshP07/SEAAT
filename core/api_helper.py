"""
SEAAT API Helper
Thin wrapper around requests for consistent error handling,
timeouts, caching, and rate-limit awareness.
"""

import time
import json
import hashlib
import os

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

CACHE_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "cache")
CACHE_TTL  = 3600  # seconds


def _cache_path(key: str) -> str:
    h = hashlib.md5(key.encode()).hexdigest()
    os.makedirs(CACHE_DIR, exist_ok=True)
    return os.path.join(CACHE_DIR, f"{h}.json")


def _load_cache(key: str):
    path = _cache_path(key)
    if not os.path.exists(path):
        return None
    try:
        with open(path) as f:
            data = json.load(f)
        if time.time() - data["_ts"] < CACHE_TTL:
            return data["payload"]
    except Exception:
        pass
    return None


def _save_cache(key: str, payload):
    path = _cache_path(key)
    try:
        with open(path, "w") as f:
            json.dump({"_ts": time.time(), "payload": payload}, f)
    except Exception:
        pass


def get(url: str, headers: dict = None, params: dict = None,
        cache_key: str = None, timeout: int = 15) -> dict:
    """
    Perform a GET request.
    Returns parsed JSON dict, or {"_error": message} on failure.
    """
    if not HAS_REQUESTS:
        return {"_error": "requests library not installed"}

    if cache_key:
        cached = _load_cache(cache_key)
        if cached is not None:
            cached["_cached"] = True
            return cached

    try:
        resp = requests.get(url, headers=headers or {}, params=params or {},
                            timeout=timeout)
        resp.raise_for_status()
        data = resp.json()
        if cache_key:
            _save_cache(cache_key, data)
        return data
    except requests.exceptions.Timeout:
        return {"_error": "Request timed out"}
    except requests.exceptions.ConnectionError:
        return {"_error": "Connection error - check network"}
    except requests.exceptions.HTTPError as e:
        return {"_error": f"HTTP {e.response.status_code}: {e.response.text[:200]}"}
    except Exception as e:
        return {"_error": str(e)}


def post(url: str, headers: dict = None, data=None,
         json_body: dict = None, timeout: int = 15) -> dict:
    """Perform a POST request."""
    if not HAS_REQUESTS:
        return {"_error": "requests library not installed"}
    try:
        resp = requests.post(url, headers=headers or {}, data=data,
                             json=json_body, timeout=timeout)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        return {"_error": str(e)}


def head_check(url: str, timeout: int = 10) -> dict:
    """HEAD request to probe a URL/domain - returns status and headers."""
    if not HAS_REQUESTS:
        return {"_error": "requests library not installed"}
    try:
        resp = requests.head(url, timeout=timeout, allow_redirects=True)
        return {
            "status_code": resp.status_code,
            "final_url": resp.url,
            "server": resp.headers.get("Server", ""),
            "content_type": resp.headers.get("Content-Type", ""),
        }
    except Exception as e:
        return {"_error": str(e)}
