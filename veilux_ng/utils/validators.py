"""
VEILUX-NG Input Validators
All user-supplied inputs are sanitised here before reaching feature modules.
"""

import re
import ipaddress
from urllib.parse import urlparse


def validate_ip(ip: str) -> bool:
    """Return True if ip is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(ip.strip())
        return True
    except ValueError:
        return False


def validate_phone(phone: str) -> bool:
    """
    Return True if phone matches a Nigerian mobile OR landline number.
    Mobile : 08031234567 | +2348031234567 | 2348031234567
    Landline: 01XXXXXXX (Lagos 8-digit) | 0XX-XXXXXXX (7-9 digits)
    """
    cleaned = re.sub(r"[\s\-()]", "", phone)
    # Mobile: starts with 0[7-9] and is 11 digits, or +234/234 prefix
    mobile = r"^(\+?234|0)[789]\d{9}$"
    # Landline: starts with 0[1-7] and is 7-10 digits total
    landline = r"^0[1-7]\d{6,8}$"
    return bool(re.match(mobile, cleaned) or re.match(landline, cleaned))


def validate_url(url: str) -> bool:
    """Return True if url has a valid http/https scheme and netloc."""
    try:
        parsed = urlparse(url)
        return parsed.scheme in ("http", "https") and bool(parsed.netloc)
    except Exception:
        return False


def validate_domain(domain: str) -> bool:
    """Return True if domain is a syntactically valid hostname."""
    pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    return bool(re.match(pattern, domain.strip()))


def validate_username(username: str) -> bool:
    """Return True if username contains only safe alphanumeric/underscore chars."""
    return bool(re.match(r"^[a-zA-Z0-9_.\-]{1,50}$", username))


def validate_mac(mac: str) -> bool:
    """Return True if mac matches standard MAC address formats."""
    pattern = r"^([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}$"
    return bool(re.match(pattern, mac.strip()))
