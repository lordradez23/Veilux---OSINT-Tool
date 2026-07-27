"""
VEILUX-NG Feature 7: Public IP Intelligence
NDPA Basis: City-level geolocation from publicly licensed GeoIP databases (Section 31).
No personal data stored. No real-time tracking.

Providers (priority order):
  1. IPinfo       — geolocation, company, ASN, privacy detection (token optional)
  2. Ipregistry   — 70+ attributes, threat levels, carrier data (key optional)
  3. MaxMind GeoIP2 — industry-standard geolocation + ISP web service (key optional)
  4. Spur         — anonymised infrastructure / VPN / residential proxy (token optional)
  5. ip-api.com   — free fallback (HTTP only)
  6. ipwho.is     — free HTTPS fallback
"""

import ipaddress
from dataclasses import dataclass, field
from typing import Optional

from config.settings import settings
from veilux_ng.core.logger import get_logger
from veilux_ng.utils.helpers import safe_request
from veilux_ng.utils.validators import validate_ip

logger = get_logger("ip_intelligence")

_IPINFO_URL     = "https://ipinfo.io/{}/json"
_IPREGISTRY_URL = "https://api.ipregistry.co/{}?key={}"
_MAXMIND_URL    = "https://geoip.maxmind.com/geoip/v2.1/insights/{}"
_SPUR_URL       = "https://api.spur.us/v2/context/{}"
_IPAPI_URL      = "http://ip-api.com/json/{}?fields=status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,proxy,hosting,query"
_IPWHOIS_URL    = "https://ipwho.is/{}"


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
    asn_name: Optional[str] = None
    hostname: Optional[str] = None
    carrier: Optional[str] = None          # mobile carrier (Ipregistry)
    company_name: Optional[str] = None     # IPinfo company
    company_domain: Optional[str] = None
    company_type: Optional[str] = None     # isp / hosting / business
    # Privacy / Threat
    is_proxy: bool = False
    is_hosting: bool = False
    is_vpn: bool = False
    is_tor: bool = False
    is_relay: bool = False                 # Apple/iCloud Private Relay
    threat_level: Optional[str] = None     # NONE / LOW / MEDIUM / HIGH (Ipregistry)
    threat_types: list[str] = field(default_factory=list)
    # Spur anonymised-infra context
    spur_tunnels: list[str] = field(default_factory=list)
    spur_infrastructure: Optional[str] = None
    # Risk
    risk_score: int = 0
    risk_flags: list[str] = field(default_factory=list)
    # Source provenance
    data_sources: list[str] = field(default_factory=list)
    notes: str = ""


class IPIntelligence:
    """
    Multi-provider IP intelligence with graceful fallback.
    Premium providers (IPinfo, Ipregistry, MaxMind, Spur) are used when API
    keys are configured; free providers fill gaps automatically.
    """

    def analyze(self, ip: str) -> IPReport:
        ip = ip.strip()
        if not validate_ip(ip):
            return IPReport(ip=ip, is_valid=False, notes="Invalid IP address format.")

        is_private = False
        try:
            addr = ipaddress.ip_address(ip)
            is_private = addr.is_private or addr.is_loopback or addr.is_reserved
        except ValueError:
            pass

        report = IPReport(ip=ip, is_valid=True, is_private=is_private)
        logger.info("Starting IP intelligence for: %s", ip)

        # --- Premium providers (run when keys present) ---
        if settings.IPINFO_TOKEN:
            self._query_ipinfo(ip, report)
        if settings.IPREGISTRY_API_KEY:
            self._query_ipregistry(ip, report)
        if settings.MAXMIND_ACCOUNT_ID and settings.MAXMIND_LICENSE_KEY:
            self._query_maxmind(ip, report)
        if settings.SPUR_API_TOKEN:
            self._query_spur(ip, report)

        # --- Free fallbacks (fill any remaining gaps) ---
        if not report.country:
            self._query_ipapi(ip, report)
        if not report.country:
            self._query_ipwhois(ip, report)

        self._calculate_risk(report)

        if report.latitude and report.longitude:
            report.maps_url = (
                f"https://www.google.com/maps?q={report.latitude},{report.longitude}"
            )

        logger.info(
            "IP intelligence complete for %s → %s, %s | risk=%d | sources=%s",
            ip, report.city, report.country, report.risk_score,
            ",".join(report.data_sources),
        )
        return report

    # ------------------------------------------------------------------
    # Premium providers
    # ------------------------------------------------------------------

    def _query_ipinfo(self, ip: str, report: IPReport) -> None:
        """IPinfo: geolocation, company, ASN, privacy detection."""
        headers = {"Authorization": f"Bearer {settings.IPINFO_TOKEN}"}
        resp = safe_request(_IPINFO_URL.format(ip), headers=headers, timeout=8)
        if not resp or resp.status_code != 200:
            return
        try:
            d = resp.json()
            report.country      = report.country      or d.get("country")
            report.region       = report.region       or d.get("region")
            report.city         = report.city         or d.get("city")
            report.postal       = report.postal       or d.get("postal")
            report.timezone     = report.timezone     or d.get("timezone")
            report.hostname     = report.hostname     or d.get("hostname")
            report.org          = report.org          or d.get("org")          # "AS#### Name"
            if not report.latitude and d.get("loc"):
                lat, lon = d["loc"].split(",")
                report.latitude, report.longitude = float(lat), float(lon)
            company = d.get("company", {})
            report.company_name   = report.company_name   or company.get("name")
            report.company_domain = report.company_domain or company.get("domain")
            report.company_type   = report.company_type   or company.get("type")
            privacy = d.get("privacy", {})
            report.is_vpn     = report.is_vpn     or bool(privacy.get("vpn"))
            report.is_proxy   = report.is_proxy   or bool(privacy.get("proxy"))
            report.is_tor     = report.is_tor     or bool(privacy.get("tor"))
            report.is_relay   = report.is_relay   or bool(privacy.get("relay"))
            report.is_hosting = report.is_hosting or bool(privacy.get("hosting"))
            report.data_sources.append("ipinfo")
        except Exception as exc:
            logger.debug("IPinfo parse error for %s: %s", ip, exc)

    def _query_ipregistry(self, ip: str, report: IPReport) -> None:
        """Ipregistry: 70+ attributes, threat levels, carrier data."""
        resp = safe_request(
            _IPREGISTRY_URL.format(ip, settings.IPREGISTRY_API_KEY), timeout=8
        )
        if not resp or resp.status_code != 200:
            return
        try:
            d = resp.json()
            loc = d.get("location", {})
            report.country      = report.country      or loc.get("country", {}).get("name")
            report.country_code = report.country_code or loc.get("country", {}).get("code")
            report.region       = report.region       or loc.get("region", {}).get("name")
            report.city         = report.city         or loc.get("city")
            report.postal       = report.postal       or loc.get("postal")
            report.timezone     = report.timezone     or loc.get("time_zone", {}).get("id")
            if not report.latitude:
                report.latitude  = loc.get("latitude")
                report.longitude = loc.get("longitude")
            conn = d.get("connection", {})
            report.asn      = report.asn      or str(conn.get("asn", "")) or None
            report.asn_name = report.asn_name or conn.get("organization")
            report.isp      = report.isp      or conn.get("isp")
            carrier = d.get("carrier", {})
            report.carrier = report.carrier or carrier.get("name")
            security = d.get("security", {})
            report.is_vpn     = report.is_vpn     or bool(security.get("is_vpn"))
            report.is_proxy   = report.is_proxy   or bool(security.get("is_proxy"))
            report.is_tor     = report.is_tor     or bool(security.get("is_tor"))
            report.is_hosting = report.is_hosting or bool(security.get("is_datacenter"))
            if not report.threat_level:
                report.threat_level = security.get("threat_level")  # NONE/LOW/MEDIUM/HIGH
            for key, label in [
                ("is_bogon", "Bogon/reserved range"),
                ("is_abuser", "Known abuser"),
                ("is_attacker", "Known attacker"),
                ("is_anonymous", "Anonymous network"),
            ]:
                if security.get(key) and label not in report.threat_types:
                    report.threat_types.append(label)
            report.data_sources.append("ipregistry")
        except Exception as exc:
            logger.debug("Ipregistry parse error for %s: %s", ip, exc)

    def _query_maxmind(self, ip: str, report: IPReport) -> None:
        """MaxMind GeoIP2 Insights web service."""
        resp = safe_request(
            _MAXMIND_URL.format(ip),
            auth=(settings.MAXMIND_ACCOUNT_ID, settings.MAXMIND_LICENSE_KEY),
            headers={"Accept": "application/json"},
            timeout=8,
        )
        if not resp or resp.status_code != 200:
            return
        try:
            d = resp.json()
            city_obj    = d.get("city", {}).get("names", {})
            country_obj = d.get("country", {}).get("names", {})
            subdiv      = (d.get("subdivisions") or [{}])[0].get("names", {})
            report.country      = report.country      or country_obj.get("en")
            report.country_code = report.country_code or d.get("country", {}).get("iso_code")
            report.region       = report.region       or subdiv.get("en")
            report.city         = report.city         or city_obj.get("en")
            report.postal       = report.postal       or d.get("postal", {}).get("code")
            report.timezone     = report.timezone     or d.get("location", {}).get("time_zone")
            if not report.latitude:
                loc = d.get("location", {})
                report.latitude  = loc.get("latitude")
                report.longitude = loc.get("longitude")
            traits = d.get("traits", {})
            report.isp      = report.isp      or traits.get("isp")
            report.org      = report.org      or traits.get("organization")
            report.asn      = report.asn      or str(traits.get("autonomous_system_number", "")) or None
            report.asn_name = report.asn_name or traits.get("autonomous_system_organization")
            report.is_proxy   = report.is_proxy   or bool(traits.get("is_anonymous_proxy"))
            report.is_hosting = report.is_hosting or bool(traits.get("is_hosting_provider"))
            report.is_tor     = report.is_tor     or bool(traits.get("is_tor_exit_node"))
            report.data_sources.append("maxmind")
        except Exception as exc:
            logger.debug("MaxMind parse error for %s: %s", ip, exc)

    def _query_spur(self, ip: str, report: IPReport) -> None:
        """Spur: anonymised infrastructure, VPN, datacenter, residential proxy context."""
        headers = {"Token": settings.SPUR_API_TOKEN}
        resp = safe_request(_SPUR_URL.format(ip), headers=headers, timeout=8)
        if not resp or resp.status_code != 200:
            return
        try:
            d = resp.json()
            tunnels = d.get("tunnels") or []
            report.spur_tunnels = [t.get("type", "") for t in tunnels if t.get("type")]
            report.spur_infrastructure = d.get("infrastructure")
            if any(t in ("VPN", "RESIDENTIAL", "DATACENTER") for t in report.spur_tunnels):
                report.is_vpn   = True
            if "TOR" in report.spur_tunnels:
                report.is_tor   = True
            if report.spur_tunnels and "Spur tunnel detected" not in report.threat_types:
                report.threat_types.append(
                    f"Spur: {', '.join(report.spur_tunnels)}"
                )
            report.data_sources.append("spur")
        except Exception as exc:
            logger.debug("Spur parse error for %s: %s", ip, exc)

    # ------------------------------------------------------------------
    # Free fallbacks
    # ------------------------------------------------------------------

    def _query_ipapi(self, ip: str, report: IPReport) -> None:
        resp = safe_request(_IPAPI_URL.format(ip), timeout=8)
        if not resp or resp.status_code != 200:
            return
        try:
            data = resp.json()
            if data.get("status") != "success":
                return
            report.country      = report.country      or data.get("country")
            report.country_code = report.country_code or data.get("countryCode")
            report.region       = report.region       or data.get("regionName")
            report.city         = report.city         or data.get("city")
            report.isp          = report.isp          or data.get("isp")
            report.asn          = report.asn          or data.get("as")
            report.is_proxy     = report.is_proxy     or bool(data.get("proxy"))
            report.is_hosting   = report.is_hosting   or bool(data.get("hosting"))
            if not report.latitude:
                report.latitude  = data.get("lat")
                report.longitude = data.get("lon")
            report.timezone = report.timezone or data.get("timezone")
            report.data_sources.append("ip-api")
        except Exception as exc:
            logger.debug("ip-api parse error for %s: %s", ip, exc)

    def _query_ipwhois(self, ip: str, report: IPReport) -> None:
        resp = safe_request(_IPWHOIS_URL.format(ip), timeout=8)
        if not resp or resp.status_code != 200:
            return
        try:
            data = resp.json()
            if data.get("success") is False:
                return
            report.country      = report.country      or data.get("country")
            report.country_code = report.country_code or data.get("country_code")
            report.region       = report.region       or data.get("region")
            report.city         = report.city         or data.get("city")
            report.postal       = report.postal       or data.get("postal")
            conn = data.get("connection", {})
            report.isp = report.isp or conn.get("isp")
            report.asn = report.asn or (str(conn.get("asn", "")) or None)
            report.timezone  = report.timezone  or data.get("timezone", {}).get("id")
            if not report.latitude:
                report.latitude  = data.get("latitude")
                report.longitude = data.get("longitude")
            report.data_sources.append("ipwho.is")
        except Exception as exc:
            logger.debug("ipwho.is parse error for %s: %s", ip, exc)

    @staticmethod
    def _calculate_risk(report: IPReport) -> None:
        score = 0
        flags = []

        if report.is_tor:
            score += 50
            flags.append("Tor exit node")
        if report.is_vpn:
            score += 35
            flags.append("VPN detected")
        if report.is_proxy:
            score += 30
            flags.append("Proxy detected")
        if report.is_relay:
            score += 20
            flags.append("Private Relay (iCloud/Apple)")
        if report.is_hosting:
            score += 20
            flags.append("Hosted on datacenter/cloud infrastructure")
        if report.spur_tunnels:
            score += 15
            flags.append(f"Spur anonymised infra: {', '.join(report.spur_tunnels)}")
        if report.threat_level in ("HIGH", "MEDIUM"):
            score += {"HIGH": 30, "MEDIUM": 15}[report.threat_level]
            flags.append(f"Ipregistry threat level: {report.threat_level}")
        flags.extend(report.threat_types)
        if not report.country:
            score += 10
            flags.append("Geolocation could not be determined")

        report.risk_score = min(score, 100)
        report.risk_flags = flags
