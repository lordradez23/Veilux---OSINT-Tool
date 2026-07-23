"""
Unit tests — Phone Analysis (carrier + full 37-zone region coverage)
"""

import pytest
from veilux_ng.features.phone_analysis import PhoneAnalysis
from veilux_ng.utils.constants import (
    NIGERIAN_MOBILE_STATE_MAP,
    ALL_36_STATES,
    _STATE_ROTATION,
)

_analyzer = PhoneAnalysis()


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------
class TestPhoneValidation:
    def test_valid_mtn(self):
        r = _analyzer.analyze("08031234567")
        assert r.is_valid is True
        assert r.carrier_name == "MTN"

    def test_valid_glo(self):
        r = _analyzer.analyze("08051234567")
        assert r.is_valid is True
        assert r.carrier_name == "Glo"

    def test_valid_airtel(self):
        r = _analyzer.analyze("08021234567")
        assert r.is_valid is True
        assert r.carrier_name == "Airtel"

    def test_valid_9mobile(self):
        r = _analyzer.analyze("08091234567")
        assert r.is_valid is True
        assert r.carrier_name == "9mobile"

    def test_valid_with_country_code(self):
        assert _analyzer.analyze("+2348031234567").is_valid is True

    def test_invalid_too_short(self):
        assert _analyzer.analyze("0803123").is_valid is False

    def test_invalid_letters(self):
        assert _analyzer.analyze("0803ABCDEFG").is_valid is False

    def test_invalid_empty(self):
        assert _analyzer.analyze("").is_valid is False

    def test_normalized_e164(self):
        assert _analyzer.analyze("08031234567").normalized == "+2348031234567"

    def test_prefix_extracted(self):
        assert _analyzer.analyze("08031234567").prefix == "0803"


# ---------------------------------------------------------------------------
# Map completeness — all 37 zones must be present
# ---------------------------------------------------------------------------
class TestMapCompleteness:
    def test_total_blocks_generated(self):
        # 33 prefix series × 10 blocks each = 330 entries
        assert len(NIGERIAN_MOBILE_STATE_MAP) == 330

    def test_all_37_zones_covered(self):
        covered = set(NIGERIAN_MOBILE_STATE_MAP.values())
        missing = [s for s in ALL_36_STATES if s not in covered]
        assert missing == [], f"Missing states: {missing}"

    def test_all_37_zones_in_rotation(self):
        assert len(_STATE_ROTATION) == 37

    @pytest.mark.parametrize("state", ALL_36_STATES)
    def test_each_state_has_at_least_one_block(self, state):
        blocks = [k for k, v in NIGERIAN_MOBILE_STATE_MAP.items() if v == state]
        assert len(blocks) >= 1, f"{state} has no prefix blocks assigned"


# ---------------------------------------------------------------------------
# Region accuracy — spot-check key states across multiple carriers
# ---------------------------------------------------------------------------
class TestRegionAccuracy:
    """
    Each 4-digit prefix series runs its own continuous slot counter.
    0803X: slot 0-9  → Lagos, Kano, Rivers, Oyo, Kaduna, Abuja(FCT), Anambra, Delta, Ogun, Enugu
    0806X: slot 10-19 → Imo, Borno, Katsina, Edo, Sokoto, Ondo, Osun, Kwara, Abia, Niger
    0805X (Glo): slot 0-9 → same as 0803X (independent series)
    """
    @pytest.mark.parametrize("number,expected_state", [
        ("08030123456", "Lagos"),
        ("08050123456", "Lagos"),   # Glo series starts fresh
        ("08020123456", "Lagos"),   # Airtel series starts fresh
        ("08090123456", "Lagos"),   # 9mobile series starts fresh
        ("07030123456", "Lagos"),   # 0703 series starts fresh
        ("09030123456", "Lagos"),   # 0903 series starts fresh
    ])
    def test_lagos_blocks(self, number, expected_state):
        r = _analyzer.analyze(number)
        assert r.region == expected_state

    @pytest.mark.parametrize("number,expected_state", [
        ("08031123456", "Kano"),
        ("08051123456", "Kano"),
        ("08021123456", "Kano"),
        ("08091123456", "Kano"),
    ])
    def test_kano_blocks(self, number, expected_state):
        r = _analyzer.analyze(number)
        assert r.region == expected_state

    @pytest.mark.parametrize("number,expected_state", [
        ("08032123456", "Rivers"),
        ("08052123456", "Rivers"),
        ("08022123456", "Rivers"),
    ])
    def test_rivers_blocks(self, number, expected_state):
        r = _analyzer.analyze(number)
        assert r.region == expected_state

    @pytest.mark.parametrize("number,expected_state", [
        ("08035123456", "Abuja (FCT)"),
        ("08055123456", "Abuja (FCT)"),
        ("08025123456", "Abuja (FCT)"),
        ("08095123456", "Abuja (FCT)"),
    ])
    def test_abuja_blocks(self, number, expected_state):
        r = _analyzer.analyze(number)
        assert r.region == expected_state

    @pytest.mark.parametrize("number,expected_state", [
        ("08036123456", "Anambra"),
        ("08056123456", "Anambra"),
        ("08026123456", "Anambra"),
    ])
    def test_anambra_blocks(self, number, expected_state):
        r = _analyzer.analyze(number)
        assert r.region == expected_state

    @pytest.mark.parametrize("number,expected_state", [
        ("08037123456", "Delta"),
        ("08057123456", "Delta"),
        ("08027123456", "Delta"),
    ])
    def test_delta_blocks(self, number, expected_state):
        r = _analyzer.analyze(number)
        assert r.region == expected_state

    @pytest.mark.parametrize("number,expected_state", [
        # 0806X series: slot 10-19
        ("08060123456", "Imo"),
        ("08061123456", "Borno"),
        ("08062123456", "Katsina"),
        ("08063123456", "Edo"),
        ("08064123456", "Sokoto"),
        ("08065123456", "Ondo"),
        ("08066123456", "Osun"),
        ("08067123456", "Kwara"),
        ("08068123456", "Abia"),
        ("08069123456", "Niger"),
    ])
    def test_0806_series_all_slots(self, number, expected_state):
        r = _analyzer.analyze(number)
        assert r.region == expected_state

    def test_region_note_always_present(self):
        r = _analyzer.analyze("08030123456")
        assert r.region_note != ""

    def test_unknown_prefix_no_crash(self):
        r = _analyzer.analyze("08991234567")
        assert r is not None


# ---------------------------------------------------------------------------
# Landline region — geographically fixed, always accurate
# ---------------------------------------------------------------------------
class TestLandlineRegion:
    @pytest.mark.parametrize("number,expected", [
        ("0112345678",  "Lagos"),
        ("0511234567",  "Port Harcourt (Rivers)"),
        ("0421234567",  "Enugu"),
        ("0781234567",  "Kano"),
        ("0311234567",  "Benin City (Edo)"),
        ("0551234567",  "Calabar (Cross River)"),
        ("0561234567",  "Uyo (Akwa Ibom)"),
        ("0471234567",  "Owerri (Imo)"),
        ("0441234567",  "Awka (Anambra)"),
        ("0611234567",  "Maiduguri (Borno)"),
        ("0621234567",  "Yola (Adamawa)"),
        ("0651234567",  "Bauchi"),
        ("0711234567",  "Sokoto"),
        ("0721234567",  "Ilorin (Kwara)"),
        ("0741234567",  "Minna (Niger)"),
        ("0761234567",  "Katsina"),
    ])
    def test_landline_regions(self, number, expected):
        r = _analyzer.analyze(number)
        assert r.region == expected
