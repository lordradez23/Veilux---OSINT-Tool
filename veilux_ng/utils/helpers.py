"""
VEILUX-NG Helper Utilities
Shared helpers used across feature modules.
"""

import hashlib
import ipaddress
import time
from typing import Optional
from urllib.parse import urlparse

import requests
from requests import Response

from veilux_ng.core.logger import get_logger

logger = get_logger("helpers")

_DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept-Language": "en-US,en;q=0.9",
}


def anonymize_ip(ip: str) -> str:
    """
    Anonymise an IP address for storage (NDPA Section 24 — data minimisation).
    IPv4: zero last octet  →  192.168.1.x
    IPv6: zero last 80 bits
    """
    try:
        addr = ipaddress.ip_address(ip)
        if addr.version == 4:
            parts = ip.split(".")
            return f"{parts[0]}.{parts[1]}.{parts[2]}.x"
        else:
            # Keep first 48 bits only
            packed = addr.packed[:6] + b"\x00" * 10
            return str(ipaddress.IPv6Address(packed)) + "/48"
    except ValueError:
        return "unknown"


def safe_request(
    url: str,
    method: str = "GET",
    timeout: int = 10,
    retries: int = 2,
    **kwargs,
) -> Optional[Response]:
    """
    Perform an HTTP request with retry logic and a consistent User-Agent.
    Returns None on failure instead of raising.
    """
    headers = {**_DEFAULT_HEADERS, **kwargs.pop("headers", {})}
    for attempt in range(retries + 1):
        try:
            resp = requests.request(
                method, url, headers=headers, timeout=timeout, **kwargs
            )
            resp.raise_for_status()
            return resp
        except requests.exceptions.HTTPError as exc:
            logger.debug("HTTP %s on %s (attempt %d)", exc.response.status_code, url, attempt + 1)
            return exc.response  # Return the response even on HTTP errors for callers to inspect
        except requests.exceptions.RequestException as exc:
            logger.warning("Request failed [%s] attempt %d/%d: %s", url, attempt + 1, retries + 1, exc)
            if attempt < retries:
                time.sleep(1.5 ** attempt)
    return None


def parse_user_agent(ua_string: str) -> dict:
    """
    Extract device type and browser family from a User-Agent string.
    Lightweight — no external library required.
    """
    ua = ua_string.lower()
    device = "Desktop"
    if any(k in ua for k in ("android", "iphone", "ipad", "mobile")):
        device = "Mobile"
    elif "tablet" in ua:
        device = "Tablet"

    browser = "Unknown"
    for name in ("chrome", "firefox", "safari", "edge", "opera", "msie", "trident"):
        if name in ua:
            browser = name.capitalize()
            break

    return {"device_type": device, "browser": browser}


def extract_domain(url: str) -> str:
    """Return the bare domain from a URL (strips www.)."""
    parsed = urlparse(url if "://" in url else f"http://{url}")
    return parsed.netloc.lstrip("www.")


def levenshtein(s1: str, s2: str) -> int:
    """Compute Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein(s2, s1)
    if not s2:
        return len(s1)
    prev = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr = [i + 1]
        for j, c2 in enumerate(s2):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (c1 != c2)))
        prev = curr
    return prev[-1]
