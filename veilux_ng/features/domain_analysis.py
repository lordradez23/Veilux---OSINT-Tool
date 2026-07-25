"""
VEILUX-NG Feature 5: Public Domain Analysis
NDPA Basis: WHOIS, DNS, and SSL are publicly mandated disclosures (Section 31).
No personal data collected beyond what registrants voluntarily publish.
"""

import ssl
import socket
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

import dns.resolver
import whois

from veilux_ng.core.exceptions import ValidationError
from veilux_ng.core.logger import get_logger
from veilux_ng.utils.helpers import safe_request
from veilux_ng.utils.validators import validate_domain

logger = get_logger("domain_analysis")

_DNS_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
_REPUTATION_API = "https://domain.opendns.com/{}"  # Public OpenDNS lookup


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

        logger.info("Domain analysis complete for: %s", domain)
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
