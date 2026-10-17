"""
Unit tests — Phone Intelligence
"""

import pytest
from veilux_ng.features.phone_analysis import PhoneAnalysis
from veilux_ng.utils.constants import (
    NIGERIAN_MOBILE_STATE_MAP,
    ALL_36_STATES,
    _STATE_ROTATION,
)

_analyzer = PhoneAnalysis()


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


class TestModuleResultBase:
    def test_module_field_set(self):
        r = _analyzer.analyze("08031234567")
        assert r.module == "phone_analysis"

    def test_input_value_field_set(self):
        r = _analyzer.analyze("08031234567")
        assert r.input_value == "08031234567"

    def test_timestamp_present(self):
        r = _analyzer.analyze("08031234567")
        assert r.timestamp != ""

    def test_invalid_phone_module_field(self):
        r = _analyzer.analyze("000")
        assert r.module == "phone_analysis"


class TestMapCompleteness:
    def test_total_blocks_generated(self):
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


class TestRegionAccuracy:
    @pytest.mark.parametrize("number,expected_state", [
        ("08030123456", "Lagos"),
        ("08050123456", "Lagos"),
        ("08020123456", "Lagos"),
        ("08090123456", "Lagos"),
        ("07030123456", "Lagos"),
        ("09030123456", "Lagos"),
    ])
    def test_lagos_blocks(self, number, expected_state):
        assert _analyzer.analyze(number).region == expected_state

    @pytest.mark.parametrize("number,expected_state", [
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
        assert _analyzer.analyze(number).region == expected_state

    def test_region_note_always_present(self):
        assert _analyzer.analyze("08030123456").region_note != ""

    def test_unknown_prefix_no_crash(self):
        assert _analyzer.analyze("08991234567") is not None


class TestVeriphone:
    def test_veriphone_fields_present_on_report(self, mocker):
        mocker.patch(
            "veilux_ng.features.phone_analysis.PhoneAnalysis._check_veriphone",
            return_value=(True, "mobile", "MTN Nigeria", "Nigeria"),
        )
        r = _analyzer.analyze("08031234567")
        assert r.veriphone_valid is True
        assert r.veriphone_line_type == "mobile"
        assert r.veriphone_carrier == "MTN Nigeria"
        assert r.veriphone_country == "Nigeria"

    def test_veriphone_unavailable_does_not_crash(self, mocker):
        mocker.patch(
            "veilux_ng.features.phone_analysis.PhoneAnalysis._check_veriphone",
            return_value=(None, None, None, None),
        )
        r = _analyzer.analyze("08031234567")
        assert r.veriphone_valid is None
        assert r.veriphone_line_type is None

    def test_veriphone_not_called_for_invalid_number(self, mocker):
        mock = mocker.patch(
            "veilux_ng.features.phone_analysis.PhoneAnalysis._check_veriphone",
        )
        _analyzer.analyze("000")
        mock.assert_not_called()

    @pytest.mark.parametrize("number,expected", [
        ("0112345678",  "Lagos"),
        ("0511234567",  "Port Harcourt (Rivers)"),
        ("0421234567",  "Enugu"),
        ("0781234567",  "Kano"),
        ("0311234567",  "Benin City (Edo)"),
        ("0551234567",  "Calabar (Cross River)"),
        ("0561234567",  "Uyo (Akwa Ibom)"),
        ("0471234567",  "Owerri (Imo)"),
    ])
    def test_landline_regions(self, number, expected):
        assert _analyzer.analyze(number).region == expected
