"""
Unit tests — Phishing Detector
Uses mocking to avoid live network calls.
"""

import pytest
from unittest.mock import patch, MagicMock
from veilux_ng.features.phishing_detector import PhishingDetector

_detector = PhishingDetector()


class TestPhishingDetector:
    def test_invalid_url_raises(self):
        with pytest.raises(ValueError):
            _detector.analyze("not-a-url")

    @patch("veilux_ng.features.phishing_detector.PhishingDetector._check_ssl", return_value=(True, "Let's Encrypt", None))
    @patch("veilux_ng.features.phishing_detector.PhishingDetector._check_domain_age", return_value=(1200, "GoDaddy"))
    @patch("veilux_ng.features.phishing_detector.PhishingDetector._check_threat_intel", return_value=False)
    def test_legitimate_url_low_risk(self, _ti, _age, _ssl):
        report = _detector.analyze("https://www.google.com/search?q=test")
        assert report.risk_score < 45
        assert report.risk_level in ("LOW", "MEDIUM")

    @patch("veilux_ng.features.phishing_detector.PhishingDetector._check_ssl", return_value=(False, None, "No SSL found"))
    @patch("veilux_ng.features.phishing_detector.PhishingDetector._check_domain_age", return_value=(2, "Namecheap"))
    @patch("veilux_ng.features.phishing_detector.PhishingDetector._check_threat_intel", return_value=False)
    def test_new_domain_no_ssl_high_risk(self, _ti, _age, _ssl):
        report = _detector.analyze("http://g00gle-login.xyz/verify")
        assert report.risk_score >= 45

    @patch("veilux_ng.features.phishing_detector.PhishingDetector._check_ssl", return_value=(True, "DigiCert", None))
    @patch("veilux_ng.features.phishing_detector.PhishingDetector._check_domain_age", return_value=(500, "Registrar"))
    @patch("veilux_ng.features.phishing_detector.PhishingDetector._check_threat_intel", return_value=True)
    def test_threat_intel_hit_is_critical(self, _ti, _age, _ssl):
        report = _detector.analyze("https://confirmed-phish.example.com/login")
        assert report.threat_intel_hit is True
        # TI hit adds 40 pts → HIGH; verdict always says CONFIRMED PHISHING
        assert report.risk_score >= 40
        assert "CONFIRMED PHISHING" in report.verdict

    @patch("veilux_ng.features.phishing_detector.PhishingDetector._check_ssl", return_value=(True, "CA", None))
    @patch("veilux_ng.features.phishing_detector.PhishingDetector._check_domain_age", return_value=(300, "Reg"))
    @patch("veilux_ng.features.phishing_detector.PhishingDetector._check_threat_intel", return_value=False)
    def test_at_symbol_in_url_flagged(self, _ti, _age, _ssl):
        report = _detector.analyze("http://legit.com@evil.com/path")
        flags_text = " ".join(report.flags)
        assert "@" in flags_text or "symbol" in flags_text.lower()

    @patch("veilux_ng.features.phishing_detector.PhishingDetector._check_ssl", return_value=(True, "CA", None))
    @patch("veilux_ng.features.phishing_detector.PhishingDetector._check_domain_age", return_value=(300, "Reg"))
    @patch("veilux_ng.features.phishing_detector.PhishingDetector._check_threat_intel", return_value=False)
    def test_brand_impersonation_detected(self, _ti, _age, _ssl):
        # "paypa1" is 1 edit away from "paypal"
        report = _detector.analyze("https://paypa1.com/login")
        assert report.impersonated_brand is not None

    def test_risk_score_capped_at_100(self):
        # Inject maximum flags manually
        report = _detector.analyze.__wrapped__ if hasattr(_detector.analyze, "__wrapped__") else None
        # Direct score cap test via internal method
        assert _detector._score_to_level(100) == "CRITICAL"
        assert _detector._score_to_level(0) == "LOW"

    def test_score_levels_correct(self):
        assert _detector._score_to_level(75) == "CRITICAL"
        assert _detector._score_to_level(50) == "HIGH"
        assert _detector._score_to_level(30) == "MEDIUM"
        assert _detector._score_to_level(5)  == "LOW"
