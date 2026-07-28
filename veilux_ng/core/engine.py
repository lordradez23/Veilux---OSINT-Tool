"""
VEILUX-NG Core Engine
Single orchestration point for all 7 OSINT features.
Every invocation is compliance-checked before execution.
"""

import re
from dataclasses import dataclass, field
from typing import Any, Optional

from veilux_ng.core.compliance import ComplianceEngine
from veilux_ng.core.logger import get_logger
from veilux_ng.core.exceptions import ValidationError
from veilux_ng.features.phishing_detector import PhishingDetector
from veilux_ng.features.social_discovery import SocialDiscovery
from veilux_ng.features.phone_analysis import PhoneAnalysis
from veilux_ng.features.domain_analysis import DomainAnalysis
from veilux_ng.features.image_analysis import ImageAnalysis
from veilux_ng.utils.validators import (
    validate_phone, validate_url, validate_domain, validate_username,
)

logger = get_logger("engine")


@dataclass
class InvestigationReport:
    identifier: str
    detected_type: str
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
            "results":       {k: _serialise(v) for k, v in self.results.items()},
            "compliance":    self.compliance,
            "errors":        self.errors,
        }


class VeiluxEngine:
    """
    Central orchestrator for VEILUX-NG.
    Auto-detects identifier type and routes to the appropriate feature(s).
    All features are NDPA 2023 compliant — public data only.
    """

    def __init__(self) -> None:
        self.phishing_detector = PhishingDetector()
        self.social_discovery  = SocialDiscovery()
        self.phone_analysis    = PhoneAnalysis()
        self.domain_analysis   = DomainAnalysis()
        self.image_analysis    = ImageAnalysis()
        self.compliance        = ComplianceEngine()
        logger.info("VeiluxEngine initialised — 5 modules loaded.")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def investigate(self, identifier: str, feature: Optional[str] = None) -> InvestigationReport:
        """
        Run OSINT on an identifier.
        If feature is specified and is not "auto", run only that module.
        Otherwise auto-detect the identifier type and run all applicable modules.
        """
        identifier = identifier.strip()

        if feature is None or feature == "auto":
            detected_type = self._detect_type(identifier)
            report = InvestigationReport(identifier=identifier, detected_type=detected_type)
            logger.info("Investigation started: identifier='%s' type='%s'", identifier[:60], detected_type)
            self._run_all(identifier, report)
        else:
            report = InvestigationReport(identifier=identifier, detected_type=feature)
            logger.info("Investigation started: identifier='%s' type='%s'", identifier[:60], feature)
            self._run_single(identifier, feature, report)

        return report

    def compliance_report(self) -> list:
        """Return the full NDPA 2023 compliance status for all features."""
        return self.compliance.full_report()

    # ------------------------------------------------------------------
    # Private routing
    # ------------------------------------------------------------------

    def _run_single(self, identifier: str, feature: str, report: InvestigationReport) -> None:
        self.compliance.assert_compliant(feature)
        compliance_result = self.compliance.check(feature)
        report.compliance[feature] = {
            "legal_basis": compliance_result.legal_basis,
            "ndpa_section": compliance_result.ndpa_section,
        }
        try:
            result = self._dispatch(identifier, feature)
            report.results[feature] = result
        except ValidationError as exc:
            logger.warning("Feature '%s' validation failed for '%s': %s", feature, identifier[:60], exc)
            report.errors[feature] = str(exc)
        except Exception as exc:
            logger.error("Feature '%s' failed for '%s': %s", feature, identifier[:60], exc)
            report.errors[feature] = str(exc)

    def _run_all(self, identifier: str, report: InvestigationReport) -> None:
        detected = self._detect_type(identifier)
        report.detected_type = detected

        feature_map = {
            "phone":   ["phone_analysis"],
            "domain":  ["domain_analysis", "phishing_detector"],
            "url":     ["phishing_detector"],
            "image":   ["image_analysis"],
            "username":["social_discovery"],
        }
        features = feature_map.get(detected, list(self._all_features()))
        for feat in features:
            self._run_single(identifier, feat, report)

    def _dispatch(self, identifier: str, feature: str) -> Any:
        dispatch_table = {
            "phishing_detector": lambda i: self.phishing_detector.analyze(i),
            "social_discovery":  lambda i: self.social_discovery.discover(i),
            "phone_analysis":    lambda i: self.phone_analysis.analyze(i),
            "domain_analysis":   lambda i: self.domain_analysis.analyze(i),
            "image_analysis":    lambda i: self.image_analysis.analyze(i),
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
        """Heuristically determine what kind of identifier was provided."""
        # Phone number
        if re.match(r"^(\+?234|0)[789]\d{9}$", re.sub(r"[\s\-()]", "", identifier)):
            return "phone"
        # Local image file path (absolute or relative, any OS separator)
        _IMAGE_EXTS = (".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp")
        if any(identifier.lower().endswith(ext) for ext in _IMAGE_EXTS):
            return "image"
        # URL
        if identifier.startswith(("http://", "https://")):
            return "url"
        # Domain
        if validate_domain(identifier):
            return "domain"
        # Username fallback
        return "username"

    @staticmethod
    def _all_features() -> list[str]:
        return [
            "phishing_detector", "social_discovery",
            "phone_analysis", "domain_analysis", "image_analysis",
        ]
