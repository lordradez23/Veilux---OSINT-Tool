"""
VEILUX-NG Core Engine
Single orchestration point for all four OSINT modules.
Every invocation is compliance-checked before execution.
"""

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from veilux_ng.core.compliance import ComplianceEngine
from veilux_ng.core.logger import get_logger
from veilux_ng.core.exceptions import ValidationError
from veilux_ng.core.result import ModuleResult
from veilux_ng.features.url_intelligence import URLIntelligence
from veilux_ng.features.social_discovery import SocialDiscovery
from veilux_ng.features.phone_analysis import PhoneAnalysis
from veilux_ng.features.ip_intelligence import IPIntelligence
from veilux_ng.utils.validators import validate_phone, validate_url, validate_domain, validate_ip

logger = get_logger("engine")

_SUPPORTED_FEATURES = frozenset([
    "phone_analysis",
    "ip_intelligence",
    "social_discovery",
    "url_intelligence",
])


@dataclass
class InvestigationReport:
    identifier: str
    detected_type: str
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    results: dict[str, Any] = field(default_factory=dict)
    compliance: dict[str, Any] = field(default_factory=dict)
    errors: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Serialise the report to a plain dict suitable for JSON export."""
        import dataclasses

        def _serialise(obj):
            if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
                return {k: _serialise(v) for k, v in dataclasses.asdict(obj).items()}
            if isinstance(obj, dict):
                return {k: _serialise(v) for k, v in obj.items()}
            if isinstance(obj, (list, tuple)):
                return [_serialise(i) for i in obj]
            return obj

        return {
            "identifier":    self.identifier,
            "detected_type": self.detected_type,
            "timestamp":     self.timestamp,
            "results":       {k: _serialise(v) for k, v in self.results.items()},
            "compliance":    self.compliance,
            "errors":        self.errors,
        }


class VeiluxEngine:
    """
    Central orchestrator for VEILUX-NG.
    Supports four modules: phone_analysis, ip_intelligence,
    social_discovery, url_intelligence.
    Auto-detects identifier type and routes to the appropriate module.
    All modules are NDPA 2023 compliant — public data only.
    """

    def __init__(self) -> None:
        self.phone_analysis    = PhoneAnalysis()
        self.ip_intelligence   = IPIntelligence()
        self.social_discovery  = SocialDiscovery()
        self.url_intelligence  = URLIntelligence()
        self.compliance        = ComplianceEngine()
        logger.info("VeiluxEngine initialised — 4 modules loaded.")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def investigate(self, identifier: str, feature: Optional[str] = None) -> InvestigationReport:
        """
        Run OSINT on an identifier.
        If feature is specified and is not 'auto', run only that module.
        Otherwise auto-detect the identifier type and run all applicable modules.
        """
        identifier = identifier.strip()

        if feature and feature != "auto":
            if feature not in _SUPPORTED_FEATURES:
                raise ValueError(
                    f"Unknown feature: '{feature}'. "
                    f"Supported: {sorted(_SUPPORTED_FEATURES)}"
                )
            report = InvestigationReport(identifier=identifier, detected_type=feature)
            logger.info("Investigation started: identifier='%s' feature='%s'", identifier[:60], feature)
            self._run_single(identifier, feature, report)
        else:
            detected_type = self._detect_type(identifier)
            report = InvestigationReport(identifier=identifier, detected_type=detected_type)
            logger.info("Investigation started: identifier='%s' type='%s'", identifier[:60], detected_type)
            self._run_all(identifier, report)

        return report

    def compliance_report(self) -> list:
        """Return the full NDPA 2023 compliance status for all four modules."""
        return self.compliance.full_report()

    # ------------------------------------------------------------------
    # Private routing
    # ------------------------------------------------------------------

    def _run_single(self, identifier: str, feature: str, report: InvestigationReport) -> None:
        self.compliance.assert_compliant(feature)
        compliance_result = self.compliance.check(feature)
        report.compliance[feature] = {
            "legal_basis":  compliance_result.legal_basis,
            "ndpa_section": compliance_result.ndpa_section,
        }
        try:
            result = self._dispatch(identifier, feature)
            report.results[feature] = result
        except ValidationError as exc:
            logger.warning("Module '%s' validation failed for '%s': %s", feature, identifier[:60], exc)
            report.errors[feature] = str(exc)
        except Exception as exc:
            logger.error("Module '%s' failed for '%s': %s", feature, identifier[:60], exc)
            report.errors[feature] = str(exc)

    def _run_all(self, identifier: str, report: InvestigationReport) -> None:
        feature_map = {
            "phone":    ["phone_analysis"],
            "ip":       ["ip_intelligence"],
            "url":      ["url_intelligence"],
            "domain":   ["url_intelligence"],
            "username": ["social_discovery"],
        }
        features = feature_map.get(report.detected_type, ["url_intelligence"])
        for feat in features:
            self._run_single(identifier, feat, report)

    def _dispatch(self, identifier: str, feature: str) -> Any:
        dispatch_table = {
            "phone_analysis":   lambda i: self.phone_analysis.analyze(i),
            "ip_intelligence":  lambda i: self.ip_intelligence.analyze(i),
            "social_discovery": lambda i: self.social_discovery.discover(i),
            "url_intelligence": lambda i: self.url_intelligence.analyze(i),
        }
        handler = dispatch_table.get(feature)
        if not handler:
            raise ValueError(f"Unknown feature: '{feature}'")
        return handler(identifier)

    # ------------------------------------------------------------------
    # Type detection
    # ------------------------------------------------------------------

    @staticmethod
    def _detect_type(identifier: str) -> str:
        """
        Determine the identifier type in strict priority order:
        1. Nigerian phone number
        2. IP address (IPv4 or IPv6)
        3. URL (http/https)
        4. Domain name
        5. Username (fallback)
        """
        cleaned = re.sub(r"[\s\-()+]", "", identifier)

        # 1. Nigerian phone
        if re.match(r"^(\+?234|0)[789]\d{9}$", cleaned):
            return "phone"

        # 2. IP address — must come before domain to avoid misclassifying IPs
        if validate_ip(identifier.strip()):
            return "ip"

        # 3. URL
        if identifier.startswith(("http://", "https://")):
            return "url"

        # 4. Domain
        if validate_domain(identifier.strip()):
            return "domain"

        # 5. Username fallback
        return "username"

    @staticmethod
    def _all_features() -> list[str]:
        return [
            "phone_analysis",
            "ip_intelligence",
            "social_discovery",
            "url_intelligence",
        ]
