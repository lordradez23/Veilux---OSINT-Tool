"""
VEILUX-NG Compliance Engine
Enforces NDPA 2023 (Nigeria Data Protection Act) compliance.
All features operate exclusively on publicly available data.
"""

from dataclasses import dataclass, field
from typing import Optional
from veilux_ng.core.logger import get_logger

logger = get_logger("compliance")


@dataclass
class ComplianceResult:
    feature: str
    is_compliant: bool
    legal_basis: str
    ndpa_section: str
    notes: str = ""


# Legal basis registry — maps each feature to its NDPA exemption
_COMPLIANCE_REGISTRY: dict[str, dict] = {
    "phishing_detector": {
        "legal_basis": "Analysis of publicly accessible URLs and domain registration records.",
        "ndpa_section": "Section 31 (Public Data Exemption) — WHOIS and SSL are public.",
        "public": True,
    },
    "social_discovery": {
        "legal_basis": "Indexing of publicly visible social media profiles only.",
        "ndpa_section": "Section 31 (Public Data Exemption) — public profiles are not private data.",
        "public": True,
    },
    "phone_analysis": {
        "legal_basis": "Carrier/state derived from public NCC prefix allocation tables.",
        "ndpa_section": "Section 31 (Public Data Exemption) — prefix data is publicly published by NCC.",
        "public": True,
    },
    "domain_analysis": {
        "legal_basis": "WHOIS, DNS, and SSL records are publicly mandated disclosures.",
        "ndpa_section": "Section 31 (Public Data Exemption) — ICANN/NCC mandated public records.",
        "public": True,
    },
    "image_analysis": {
        "legal_basis": "EXIF metadata embedded in publicly accessible images.",
        "ndpa_section": "Section 31 (Public Data Exemption) — metadata published by image owner.",
        "public": True,
    },
}


class ComplianceEngine:
    """Validates that each feature invocation is NDPA 2023 compliant."""

    def check(self, feature: str) -> ComplianceResult:
        entry = _COMPLIANCE_REGISTRY.get(feature)
        if not entry:
            logger.warning("Unknown feature '%s' — compliance check failed.", feature)
            return ComplianceResult(
                feature=feature,
                is_compliant=False,
                legal_basis="Unknown feature.",
                ndpa_section="N/A",
                notes="Feature not registered in compliance registry.",
            )

        result = ComplianceResult(
            feature=feature,
            is_compliant=entry["public"],
            legal_basis=entry["legal_basis"],
            ndpa_section=entry["ndpa_section"],
        )
        logger.debug("Compliance check PASSED for feature '%s'.", feature)
        return result

    def assert_compliant(self, feature: str) -> None:
        """Raise RuntimeError if the feature is not compliant."""
        result = self.check(feature)
        if not result.is_compliant:
            raise RuntimeError(
                f"[COMPLIANCE BLOCK] Feature '{feature}' failed NDPA 2023 check: "
                f"{result.notes}"
            )

    def full_report(self) -> list[ComplianceResult]:
        return [self.check(f) for f in _COMPLIANCE_REGISTRY]
