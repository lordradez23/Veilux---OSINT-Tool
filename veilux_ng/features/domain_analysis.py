"""
VEILUX-NG Feature 5: Public Domain Analysis
NDPA Basis: WHOIS, DNS, and SSL are publicly mandated disclosures (Section 31).
No personal data collected beyond what registrants voluntarily publish.

Extra providers (optional API keys):
  DomScan      — availability, valuation, DNS (10,000 free credits/month)
  Ahrefs       — domain rating metric (free developer endpoint)
  API Ninjas   — WHOIS + DNS fallback (free tier, non-commercial)
"""

import ssl
import socket
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

import dns.resolver
import whois

from config.settings import settings
from veilux_ng.core.exceptions import ValidationError
from veilux_ng.core.logger import get_logger
from veilux_ng.utils.helpers import safe_request
from veilux_ng.utils.validators import validate_domain

logger = get_logger("domain_analysis")

_DNS_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]

_DOMSCAN_AVAIL_URL   = "https://api.domscan.io/v1/domain/availability?domain={}"
_DOMSCAN_VALUE_URL   = "https://api.domscan.io/v1/domain/valuation?domain={}"
_DOMSCAN_DNS_URL     = "https://api.domscan.io/v1/domain/dns?domain={}"
_AHREFS_DR_URL       = "https://api.ahrefs.com/v3/site-explorer/domain-rating?target={}&output=json"
_APININJAS_WHOIS_URL = "https://api.api-ninjas.com/v1/whois?domain={}"
_APININJAS_DNS_URL   = "https://api.api-ninjas.com/v1/dnslookup?domain={}"


@dataclass
class SSLInfo:
    valid: bool
    issuer: Optional[str] = None
    subject: Optional[str] = None
    expires: Optional[str] = None
    days_until_expiry: Optional[int] = None
    error: Optional[str] = None


@dataclass
class DomainReport:
    domain: str
    registrar: Optional[str] = None
    registered_on: Optional[str] = None
    expires_on: Optional[str] = None
    age_days: Optional[int] = None
    registrant_country: Optional[str] = None
    name_servers: list[str] = field(default_factory=list)
    dns_records: dict[str, list[str]] = field(default_factory=dict)
    ssl: Optional[SSLInfo] = None
    hosting_ip: Optional[str] = None
    hosting_org: Optional[str] = None
    reputation: Optional[str] = None
    # DomScan
    is_available: Optional[bool] = None
    valuation_usd: Optional[float] = None
    # Ahrefs
    domain_rating: Optional[float] = None
    ahrefs_rank: Optional[int] = None
    # API Ninjas (fallback WHOIS/DNS)
    whois_api_registrar: Optional[str] = None
    whois_api_created: Optional[str] = None
    whois_api_expires: Optional[str] = None
    dns_api_records: dict[str, list[str]] = field(default_factory=dict)
    # Provenance
    data_sources: list[str] = field(default_factory=list)
    notes: str = ""


class DomainAnalysis:
    """
    Gathers comprehensive public domain intelligence:
    WHOIS records, DNS records, SSL certificate info, and hosting details.
    """

    def analyze(self, domain: str) -> DomainReport:
        domain = domain.strip().lower().lstrip("www.")
        if not validate_domain(domain):
            raise ValidationError(f"Invalid domain: {domain}")

        report = DomainReport(domain=domain)
        logger.info("Starting domain analysis for: %s", domain)

        self._run_whois(domain, report)
        self._run_dns(domain, report)
        self._run_ssl(domain, report)
        self._run_hosting(domain, report)

        # --- Optional premium providers ---
        if settings.DOMSCAN_API_KEY:
            self._query_domscan(domain, report)
        if settings.AHREFS_API_KEY:
            self._query_ahrefs(domain, report)
        if settings.APININJAS_API_KEY:
            self._query_apininjas(domain, report)

        logger.info(
            "Domain analysis complete for %s | sources=%s",
            domain, ",".join(report.data_sources) or "local",
        )
        return report

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _run_whois(self, domain: str, report: DomainReport) -> None:
        try:
            w = whois.whois(domain)
            report.registrar = w.registrar

            created = w.creation_date
            if isinstance(created, list):
                created = created[0]
            if created:
                if created.tzinfo is None:
                    created = created.replace(tzinfo=timezone.utc)
                report.registered_on = created.strftime("%Y-%m-%d")
                report.age_days = (datetime.now(timezone.utc) - created).days

            expires = w.expiration_date
            if isinstance(expires, list):
                expires = expires[0]
            if expires:
                report.expires_on = expires.strftime("%Y-%m-%d") if hasattr(expires, "strftime") else str(expires)

            ns = w.name_servers
            if ns:
                report.name_servers = sorted({n.lower() for n in ns if n})

            report.registrant_country = getattr(w, "country", None)
        except Exception as exc:
            logger.debug("WHOIS failed for %s: %s", domain, exc)
            report.notes += "WHOIS lookup failed. "

    def _run_dns(self, domain: str, report: DomainReport) -> None:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5

        for rtype in _DNS_RECORD_TYPES:
            try:
                answers = resolver.resolve(domain, rtype)
                report.dns_records[rtype] = [r.to_text() for r in answers]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass
            except Exception as exc:
                logger.debug("DNS %s query failed for %s: %s", rtype, domain, exc)

    def _run_ssl(self, domain: str, report: DomainReport) -> None:
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(
                socket.create_connection((domain, 443), timeout=6),
                server_hostname=domain,
            ) as s:
                cert = s.getpeercert()
                issuer = dict(x[0] for x in cert.get("issuer", []))
                subject = dict(x[0] for x in cert.get("subject", []))
                not_after = cert.get("notAfter", "")
                expiry = None
                days_left = None
                if not_after:
                    expiry_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    expiry = expiry_dt.strftime("%Y-%m-%d")
                    days_left = (expiry_dt - datetime.now(timezone.utc)).days

                report.ssl = SSLInfo(
                    valid=True,
                    issuer=issuer.get("organizationName"),
                    subject=subject.get("commonName"),
                    expires=expiry,
                    days_until_expiry=days_left,
                )
        except ssl.CertificateError as exc:
            report.ssl = SSLInfo(valid=False, error=str(exc))
        except (socket.timeout, ConnectionRefusedError, OSError):
            report.ssl = SSLInfo(valid=False, error="Could not establish SSL connection")
        except Exception as exc:
            report.ssl = SSLInfo(valid=False, error=str(exc))

    def _run_hosting(self, domain: str, report: DomainReport) -> None:
        try:
            ip = socket.gethostbyname(domain)
            report.hosting_ip = ip
            resp = safe_request(f"https://ipinfo.io/{ip}/json", timeout=6)
            if resp and resp.status_code == 200:
                data = resp.json()
                report.hosting_org = data.get("org")
        except Exception as exc:
            logger.debug("Hosting lookup failed for %s: %s", domain, exc)

    # ------------------------------------------------------------------
    # Optional premium providers
    # ------------------------------------------------------------------

    def _query_domscan(self, domain: str, report: DomainReport) -> None:
        """DomScan: availability, valuation, DNS (10,000 free credits/month)."""
        headers = {"Authorization": f"Bearer {settings.DOMSCAN_API_KEY}"}
        try:
            hit = False
            avail = safe_request(_DOMSCAN_AVAIL_URL.format(domain), headers=headers, timeout=8)
            if avail and avail.status_code == 200:
                report.is_available = avail.json().get("available")
                hit = True

            val = safe_request(_DOMSCAN_VALUE_URL.format(domain), headers=headers, timeout=8)
            if val and val.status_code == 200:
                report.valuation_usd = val.json().get("value")
                hit = True

            dns_resp = safe_request(_DOMSCAN_DNS_URL.format(domain), headers=headers, timeout=8)
            if dns_resp and dns_resp.status_code == 200:
                records = dns_resp.json().get("records", {})
                for rtype, values in records.items():
                    if rtype not in report.dns_records:
                        report.dns_records[rtype] = values if isinstance(values, list) else [values]
                hit = True

            if hit:
                report.data_sources.append("domscan")
        except Exception as exc:
            logger.debug("DomScan failed for %s: %s", domain, exc)

    def _query_ahrefs(self, domain: str, report: DomainReport) -> None:
        """Ahrefs for Developers: domain rating + Ahrefs rank (free endpoint)."""
        headers = {"Authorization": f"Bearer {settings.AHREFS_API_KEY}"}
        try:
            resp = safe_request(_AHREFS_DR_URL.format(domain), headers=headers, timeout=8)
            if not resp or resp.status_code != 200:
                return
            d = resp.json().get("domain_rating", {})
            report.domain_rating = d.get("domain_rating")
            report.ahrefs_rank   = d.get("ahrefs_rank")
            report.data_sources.append("ahrefs")
        except Exception as exc:
            logger.debug("Ahrefs failed for %s: %s", domain, exc)

    def _query_apininjas(self, domain: str, report: DomainReport) -> None:
        """API Ninjas: WHOIS fallback + DNS fallback (free tier, non-commercial)."""
        headers = {"X-Api-Key": settings.APININJAS_API_KEY}
        try:
            hit = False
            # WHOIS — fill gaps left by python-whois
            w = safe_request(_APININJAS_WHOIS_URL.format(domain), headers=headers, timeout=8)
            if w and w.status_code == 200:
                wd = w.json()
                report.whois_api_registrar = wd.get("registrar")
                report.whois_api_created   = wd.get("creation_date")
                report.whois_api_expires   = wd.get("expiration_date")
                if not report.registrar:
                    report.registrar = report.whois_api_registrar
                if not report.registered_on:
                    report.registered_on = report.whois_api_created
                if not report.expires_on:
                    report.expires_on = report.whois_api_expires
                hit = True

            # DNS — fill gaps left by dnspython
            d = safe_request(_APININJAS_DNS_URL.format(domain), headers=headers, timeout=8)
            if d and d.status_code == 200:
                for rec in d.json():
                    rtype = rec.get("record_type", "").upper()
                    value = rec.get("value", "")
                    if rtype and value:
                        report.dns_api_records.setdefault(rtype, []).append(value)
                        if rtype not in report.dns_records:
                            report.dns_records.setdefault(rtype, []).append(value)
                hit = True

            if hit:
                report.data_sources.append("api-ninjas")
        except Exception as exc:
            logger.debug("API Ninjas failed for %s: %s", domain, exc)
