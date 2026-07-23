"""
VEILUX-NG Feature 4: Nigerian Phone Number Analysis
NDPA Basis: Carrier/state derived from NCC public prefix allocation tables (Section 31).
No real-time location tracking. No personal data stored.

Region accuracy notes:
- Mobile numbers: matched against NCC 5-digit allocation blocks (0XXXX)
  which reflect the state of INITIAL registration. Number portability means
  the subscriber may have moved — this is the best accuracy possible from
  public data alone.
- Landline numbers: matched via longest-prefix against NCC area codes.
  These are geographically fixed and always accurate.
"""

import re
from dataclasses import dataclass
from typing import Optional

import phonenumbers
from phonenumbers import geocoder, carrier, timezone as pn_timezone

from veilux_ng.core.logger import get_logger
from veilux_ng.utils.constants import (
    NIGERIAN_CARRIER_MAP,
    NIGERIAN_MOBILE_STATE_MAP,
    NIGERIAN_LANDLINE_MAP,
)
from veilux_ng.utils.helpers import safe_request
from veilux_ng.utils.validators import validate_phone

logger = get_logger("phone_analysis")

_NIGERIA_CODE = "NG"
_SCAM_CHECK_URL = "https://api.shouldianswer.net/v1/phone/{}"


@dataclass
class PhoneReport:
    raw_input: str
    normalized: str
    is_valid: bool
    carrier_name: Optional[str] = None
    network_type: str = "Mobile"
    country: Optional[str] = None
    region: Optional[str] = None
    region_note: str = ""
    prefix: Optional[str] = None
    timezones: Optional[list] = None
    scam_reports: Optional[int] = None
    scam_score: Optional[float] = None
    notes: str = ""


class PhoneAnalysis:
    """
    Analyses Nigerian phone numbers using public NCC prefix data.
    Region is resolved via:
      1. 5-digit mobile allocation block  (most specific for mobile)
      2. Landline area code longest-prefix match (for 01x / 02x / 03x etc.)
      3. phonenumbers geocoder fallback
    """

    def analyze(self, phone_number: str) -> PhoneReport:
        raw = phone_number.strip()

        if not validate_phone(raw):
            return PhoneReport(
                raw_input=raw,
                normalized=raw,
                is_valid=False,
                notes="Does not match Nigerian phone number format.",
            )

        normalized = self._normalize(raw)
        local = self._to_local(normalized)
        is_landline = self._is_landline(raw)
        prefix_4 = local[:4]
        prefix_5 = local[:5]

        # --- phonenumbers parse (mobile only) ---
        carrier_name = None
        timezones: list = []
        pn_region = ""
        if not is_landline:
            try:
                parsed = phonenumbers.parse(normalized, _NIGERIA_CODE)
                is_valid = phonenumbers.is_valid_number(parsed)
                country = geocoder.description_for_number(parsed, "en") or "Nigeria"
                carrier_name = carrier.name_for_number(parsed, "en") or None
                timezones = list(pn_timezone.time_zones_for_number(parsed))
                pn_region = geocoder.description_for_number(parsed, "en") or ""
            except phonenumbers.NumberParseException:
                is_valid = False
                country = "Nigeria"
        else:
            is_valid = True
            country = "Nigeria"
            network_type = "Landline"

        # --- Carrier fallback (mobile only) ---
        if not carrier_name and not is_landline:
            carrier_name = NIGERIAN_CARRIER_MAP.get(prefix_4, "Unknown")

        # --- Region resolution ---
        region, region_note = self._resolve_region(local, prefix_5, prefix_4, pn_region)

        # --- Scam check ---
        scam_reports, scam_score = self._check_scam(normalized)

        report = PhoneReport(
            raw_input=raw,
            normalized=normalized,
            is_valid=is_valid,
            carrier_name=carrier_name if not is_landline else "Landline",
            network_type="Landline" if is_landline else "Mobile",
            country=country,
            region=region,
            region_note=region_note,
            prefix=prefix_4,
            timezones=timezones,
            scam_reports=scam_reports,
            scam_score=scam_score,
        )
        logger.info(
            "Phone analysis: %s → carrier=%s region=%s",
            prefix_4, report.carrier_name, region,
        )
        return report

    # ------------------------------------------------------------------
    # Region resolution
    # ------------------------------------------------------------------

    @staticmethod
    def _resolve_region(
        local: str,
        prefix_5: str,
        prefix_4: str,
        pn_region: str,
    ) -> tuple[Optional[str], str]:
        """
        Returns (region_string, note_about_accuracy).

        Strategy:
        1. Mobile 5-digit block map  → highest specificity for mobile
        2. Landline longest-prefix   → accurate for 01x/02x/03x/etc.
        3. phonenumbers geocoder     → broad fallback
        """
        # 1. Mobile 5-digit block
        if prefix_5 in NIGERIAN_MOBILE_STATE_MAP:
            return (
                NIGERIAN_MOBILE_STATE_MAP[prefix_5],
                "Based on NCC initial registration block (number portability may apply).",
            )

        # 2. Landline longest-prefix match (try 3-digit, then 2-digit)
        for length in (3, 2):
            key = local[:length]
            if key in NIGERIAN_LANDLINE_MAP:
                return (
                    NIGERIAN_LANDLINE_MAP[key],
                    "Based on NCC landline area code (geographically fixed).",
                )

        # 3. phonenumbers geocoder fallback
        if pn_region and pn_region.lower() not in ("nigeria", ""):
            return pn_region, "Based on phonenumbers library geocoder."

        return None, "Region could not be determined from public data."

    # ------------------------------------------------------------------
    # Normalisation helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _is_landline(phone: str) -> bool:
        """Return True if the number is a Nigerian landline (starts with 01-07X area codes)."""
        cleaned = re.sub(r"[\s\-()+]", "", phone)
        return bool(re.match(r"^0[1-7]\d{6,8}$", cleaned))

    @staticmethod
    def _normalize(phone: str) -> str:
        """Convert mobile numbers to E.164. Landlines kept in local format."""
        cleaned = re.sub(r"[\s\-()+]", "", phone)
        if re.match(r"^0[1-7]\d{6,8}$", cleaned):
            return cleaned
        if cleaned.startswith("234"):
            return "+" + cleaned
        if cleaned.startswith("0"):
            return "+234" + cleaned[1:]
        return "+" + cleaned

    @staticmethod
    def _to_local(normalized: str) -> str:
        """Convert E.164 to local format (0XXXXXXXXXX). Landlines already local."""
        if normalized.startswith("+234"):
            return "0" + normalized[4:]
        return normalized

    @staticmethod
    def _extract_prefix(normalized: str) -> Optional[str]:
        local = "0" + normalized[4:] if normalized.startswith("+234") else normalized
        return local[:4] if len(local) >= 4 else None

    # ------------------------------------------------------------------
    # Scam check
    # ------------------------------------------------------------------

    @staticmethod
    def _check_scam(normalized: str) -> tuple[Optional[int], Optional[float]]:
        number = normalized.lstrip("+")
        resp = safe_request(_SCAM_CHECK_URL.format(number), timeout=6)
        if resp and resp.status_code == 200:
            try:
                data = resp.json()
                return data.get("reports", 0), data.get("score", 0.0)
            except Exception:
                pass
        return None, None
