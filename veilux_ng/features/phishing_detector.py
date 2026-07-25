"""
VEILUX-NG Feature 2: Phishing Link Detector
NDPA Basis: Analyses publicly accessible URLs and domain registration records (Section 31).
No personal data collected or stored.
"""

import ssl
import socket
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

import whois

from veilux_ng.core.exceptions import ValidationError
from veilux_ng.core.logger import get_logger
from veilux_ng.utils.helpers import safe_request, extract_domain, levenshtein
from veilux_ng.utils.constants import KNOWN_BRANDS
from veilux_ng.utils.validators import validate_url

logger = get_logger("phishing_detector")

# Risk weight configuration
_WEIGHTS = {
    "domain_age_new":        25,   # domain < 30 days old
    "domain_age_very_new":   15,   # domain < 90 days old
    "no_ssl":                20,   # no valid HTTPS cert
    "ssl_mismatch":          15,   # cert CN doesn't match domain
    "brand_impersonation":   30,   # typosquatting a known brand
    "suspicious_tld":        10,   # .xyz, .tk, .ml, .ga, .cf, .gq
    "ip_in_url":             15,   # raw IP used instead of domain
    "excessive_subdomains":  10,   # 4+ subdomains
    "long_url":               5,   # URL > 100 chars
    "at_symbol":             20,   # @ in URL (classic phishing trick)
    "double_slash_redirect": 15,   # // redirect in path
    "threat_intel_hit":      40,   # found in OpenPhish feed
}

_SUSPICIOUS_TLDS = {".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".click", ".loan", ".work"}


@dataclass
class PhishingReport:
    url: str
    domain: str
    risk_score: int                        # 0–100
    risk_level: str                        # LOW / MEDIUM / HIGH / CRITICAL
    flags: list[str] = field(default_factory=list)
    domain_age_days: Optional[int] = None
    ssl_valid: Optional[bool] = None
    ssl_issuer: Optional[str] = None
    impersonated_brand: Optional[str] = None
    threat_intel_hit: bool = False
    whois_registrar: Optional[str] = None
    verdict: str = ""


class PhishingDetector:
    """
    Analyses a URL for phishing indicators and returns a scored risk report.
    Uses only public data: WHOIS, SSL, OpenPhish feed, URL structure analysis.
    """

    _OPENPHISH_FEED = "https://openphish.com/feed.txt"
    _openphish_cache: set[str] = set()
    _cache_loaded: bool = False

    def analyze(self, url: str) -> PhishingReport:
        if not validate_url(url):
            raise ValidationError(f"Invalid URL: {url}")

        domain = extract_domain(url)
        flags: list[str] = []
        score = 0

        # --- Structural checks (no network) ---
        score, flags = self._check_url_structure(url, domain, score, flags)

        # --- SSL check ---
        ssl_valid, ssl_issuer, ssl_flag = self._check_ssl(domain)
        if ssl_flag:
            flags.append(ssl_flag)
            score += _WEIGHTS["no_ssl"] if not ssl_valid else _WEIGHTS["ssl_mismatch"]

        # --- WHOIS / domain age ---
        age_days, registrar = self._check_domain_age(domain)
        if age_days is not None:
            if age_days < 30:
                flags.append(f"Domain registered only {age_days} day(s) ago")
                score += _WEIGHTS["domain_age_new"]
            elif age_days < 90:
                flags.append(f"Domain is relatively new ({age_days} days old)")
                score += _WEIGHTS["domain_age_very_new"]

        # --- Brand impersonation ---
        brand = self._check_brand_impersonation(domain)
        if brand:
            flags.append(f"Possible impersonation of '{brand}'")
            score += _WEIGHTS["brand_impersonation"]

        # --- Threat intelligence ---
        ti_hit = self._check_threat_intel(url)
        if ti_hit:
            flags.append("URL found in OpenPhish threat intelligence feed")
            score += _WEIGHTS["threat_intel_hit"]

        score = min(score, 100)
        risk_level = self._score_to_level(score)

        report = PhishingReport(
            url=url,
            domain=domain,
            risk_score=score,
            risk_level=risk_level,
            flags=flags,
            domain_age_days=age_days,
            ssl_valid=ssl_valid,
            ssl_issuer=ssl_issuer,
            impersonated_brand=brand,
            threat_intel_hit=ti_hit,
            whois_registrar=registrar,
            verdict=self._verdict(score, ti_hit),
        )
        logger.info("Phishing analysis [%s] → score=%d (%s)", domain, score, risk_level)
        return report

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _check_url_structure(self, url: str, domain: str, score: int, flags: list) -> tuple[int, list]:
        # IP address used as host
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain):
            flags.append("Raw IP address used instead of domain name")
            score += _WEIGHTS["ip_in_url"]

        # @ symbol in URL
        if "@" in url:
            flags.append("'@' symbol detected in URL (classic phishing redirect)")
            score += _WEIGHTS["at_symbol"]

        # Double-slash redirect
        if re.search(r"https?://[^/]+/.*//", url):
            flags.append("Double-slash redirect pattern detected in URL path")
            score += _WEIGHTS["double_slash_redirect"]

        # Excessive subdomains
        subdomain_count = domain.count(".")
        if subdomain_count >= 4:
            flags.append(f"Excessive subdomains ({subdomain_count} dots in domain)")
            score += _WEIGHTS["excessive_subdomains"]

        # Long URL
        if len(url) > 100:
            flags.append(f"Unusually long URL ({len(url)} characters)")
            score += _WEIGHTS["long_url"]

        # Suspicious TLD
        tld = "." + domain.rsplit(".", 1)[-1].lower() if "." in domain else ""
        if tld in _SUSPICIOUS_TLDS:
            flags.append(f"Suspicious TLD detected: {tld}")
            score += _WEIGHTS["suspicious_tld"]

        return score, flags

    def _check_ssl(self, domain: str) -> tuple[Optional[bool], Optional[str], Optional[str]]:
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.create_connection((domain, 443), timeout=5), server_hostname=domain) as s:
                cert = s.getpeercert()
                issuer = dict(x[0] for x in cert.get("issuer", []))
                return True, issuer.get("organizationName", "Unknown CA"), None
        except ssl.CertificateError:
            return False, None, "SSL certificate does not match domain"
        except (socket.timeout, ConnectionRefusedError, OSError):
            return False, None, "No valid SSL/TLS certificate found (HTTP only)"
        except Exception:
            return None, None, None

    def _check_domain_age(self, domain: str) -> tuple[Optional[int], Optional[str]]:
        try:
            w = whois.whois(domain)
            creation = w.creation_date
            if isinstance(creation, list):
                creation = creation[0]
            if creation:
                if creation.tzinfo is None:
                    creation = creation.replace(tzinfo=timezone.utc)
                age = (datetime.now(timezone.utc) - creation).days
                return age, w.registrar
        except Exception as exc:
            logger.debug("WHOIS failed for %s: %s", domain, exc)
        return None, None

    def _check_brand_impersonation(self, domain: str) -> Optional[str]:
        bare = domain.split(".")[0].lower()
        for brand in KNOWN_BRANDS:
            if brand == bare:
                continue  # exact match is fine
            dist = levenshtein(bare, brand)
            # Flag if very close but not identical, and domain is not a known subdomain
            if dist <= 2 and len(bare) > 3:
                return brand
        return None

    def _check_threat_intel(self, url: str) -> bool:
        if not self.__class__._cache_loaded:
            self._load_openphish()
        return url.strip() in self.__class__._openphish_cache

    def _load_openphish(self) -> None:
        resp = safe_request(self._OPENPHISH_FEED, timeout=8)
        if resp and resp.status_code == 200:
            self.__class__._openphish_cache = set(resp.text.strip().splitlines())
            logger.info("OpenPhish feed loaded: %d entries", len(self.__class__._openphish_cache))
        else:
            logger.warning("Could not load OpenPhish feed — threat intel check skipped.")
        self.__class__._cache_loaded = True

    @staticmethod
    def _score_to_level(score: int) -> str:
        if score >= 70:
            return "CRITICAL"
        if score >= 45:
            return "HIGH"
        if score >= 20:
            return "MEDIUM"
        return "LOW"

    @staticmethod
    def _verdict(score: int, ti_hit: bool) -> str:
        if ti_hit:
            return "CONFIRMED PHISHING — present in threat intelligence feed."
        if score >= 70:
            return "LIKELY PHISHING — multiple high-risk indicators detected."
        if score >= 45:
            return "SUSPICIOUS — manual review recommended."
        if score >= 20:
            return "LOW RISK — minor indicators present."
        return "CLEAN — no significant phishing indicators detected."
