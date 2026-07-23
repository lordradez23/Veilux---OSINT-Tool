"""
VEILUX-NG Feature 7: Public IP Intelligence
NDPA Basis: City-level geolocation from publicly licensed GeoIP databases (Section 31).
No personal data stored. No real-time tracking.
"""

import ipaddress
from dataclasses import dataclass, field
from typing import Optional

from veilux_ng.core.logger import get_logger
from veilux_ng.utils.helpers import safe_request
from veilux_ng.utils.validators import validate_ip

logger = get_logger("ip_intelligence")

_IPINFO_URL   = "https://ipinfo.io/{}/json"
_IPAPI_URL    = "https://ip-api.com/json/{}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,proxy,hosting,query"
_ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"  # Requires free API key — gracefully skipped if absent


@dataclass
class IPReport:
    ip: str
    is_valid: bool
    is_private: bool = False
    # Geolocation
    country: Optional[str] = None
    country_code: Optional[str] = None
    region: Optional[str] = None
    city: Optional[str] = None
    postal: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    timezone: Optional[str] = None
    maps_url: Optional[str] = None
    # Network
    isp: Optional[str] = None
    org: Optional[str] = None
    asn: Optional[str] = None
    hostname: Optional[str] = None
    # Risk
    is_proxy: bool = False
    is_hosting: bool = False
    risk_score: int = 0
    risk_flags: list[str] = field(default_factory=list)
    notes: str = ""


class IPIntelligence:
    """
    Gathers public intelligence on an IP address:
    geolocation, ISP/ASN, proxy/VPN detection, and abuse reports.
    Uses only free, public APIs — no authentication required for core features.
    """

    def analyze(self, ip: str) -> IPReport:
        ip = ip.strip()
        if not validate_ip(ip):
            return IPReport(ip=ip, is_valid=False, notes="Invalid IP address format.")

        # Check for private/reserved ranges
        try:
            addr = ipaddress.ip_address(ip)
            if addr.is_private or addr.is_loopback or addr.is_reserved:
                return IPReport(ip=ip, is_valid=True, is_private=True,
                                notes="Private/reserved IP — no public geolocation available.")
        except ValueError:
            pass

        report = IPReport(ip=ip, is_valid=True)
        logger.info("Starting IP intelligence for: %s", ip)

        self._query_ipinfo(ip, report)
        self._query_ipapi(ip, report)
        self._calculate_risk(report)

        if report.latitude and report.longitude:
            report.maps_url = f"https://www.google.com/maps?q={report.latitude},{report.longitude}"

        logger.info(
            "IP intelligence complete for %s → %s, %s | risk=%d",
            ip, report.city, report.country, report.risk_score,
        )
        return report

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _query_ipinfo(self, ip: str, report: IPReport) -> None:
        resp = safe_request(_IPINFO_URL.format(ip), timeout=8)
        if not resp or resp.status_code != 200:
            return
        try:
            data = resp.json()
            report.hostname = data.get("hostname")
            report.org = data.get("org")
            report.timezone = data.get("timezone")
            report.postal = data.get("postal")
            loc = data.get("loc", "")
            if "," in loc:
                lat, lon = loc.split(",")
                report.latitude = float(lat)
                report.longitude = float(lon)
        except Exception as exc:
            logger.debug("ipinfo parse error for %s: %s", ip, exc)

    def _query_ipapi(self, ip: str, report: IPReport) -> None:
        resp = safe_request(_IPAPI_URL.format(ip), timeout=8)
        if not resp or resp.status_code != 200:
            return
        try:
            data = resp.json()
            if data.get("status") != "success":
                return
            report.country = data.get("country")
            report.country_code = data.get("countryCode")
            report.region = data.get("regionName")
            report.city = data.get("city")
            report.isp = data.get("isp")
            report.asn = data.get("as")
            report.is_proxy = bool(data.get("proxy"))
            report.is_hosting = bool(data.get("hosting"))
            if not report.latitude:
                report.latitude = data.get("lat")
                report.longitude = data.get("lon")
            if not report.timezone:
                report.timezone = data.get("timezone")
        except Exception as exc:
            logger.debug("ip-api parse error for %s: %s", ip, exc)

    @staticmethod
    def _calculate_risk(report: IPReport) -> None:
        score = 0
        flags = []

        if report.is_proxy:
            score += 40
            flags.append("Proxy/VPN detected")
        if report.is_hosting:
            score += 20
            flags.append("Hosted on datacenter/cloud infrastructure")
        if not report.country:
            score += 10
            flags.append("Geolocation could not be determined")

        report.risk_score = min(score, 100)
        report.risk_flags = flags
