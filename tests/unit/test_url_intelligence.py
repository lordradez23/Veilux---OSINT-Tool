"""
Unit tests — URL Intelligence
"""

import pytest
from unittest.mock import patch
from veilux_ng.features.url_intelligence import URLIntelligence

_analyzer = URLIntelligence()


class TestValidation:
    def test_invalid_url_raises(self):
        with pytest.raises(ValueError):
            _analyzer.analyze("not-a-url")

    def test_no_scheme_raises(self):
        with pytest.raises(ValueError):
            _analyzer.analyze("example.com")

    def test_empty_raises(self):
        with pytest.raises(ValueError):
            _analyzer.analyze("")


class TestModuleResultBase:
    @patch("veilux_ng.features.url_intelligence.URLIntelligence._check_ssl", return_value=(True, "CA", None))
    @patch("veilux_ng.features.url_intelligence.URLIntelligence._check_domain_age", return_value=(500, "Reg"))
    @patch("veilux_ng.features.url_intelligence.URLIntelligence._check_threat_intel", return_value=False)
    def test_module_field(self, _ti, _age, _ssl):
        r = _analyzer.analyze("https://example.com")
        assert r.module == "url_intelligence"

    @patch("veilux_ng.features.url_intelligence.URLIntelligence._check_ssl", return_value=(True, "CA", None))
    @patch("veilux_ng.features.url_intelligence.URLIntelligence._check_domain_age", return_value=(500, "Reg"))
    @patch("veilux_ng.features.url_intelligence.URLIntelligence._check_threat_intel", return_value=False)
    def test_input_value_field(self, _ti, _age, _ssl):
        r = _analyzer.analyze("https://example.com")
        assert r.input_value == "https://example.com"


class TestRiskScoring:
    @patch("veilux_ng.features.url_intelligence.URLIntelligence._check_ssl", return_value=(True, "Let's Encrypt", None))
    @patch("veilux_ng.features.url_intelligence.URLIntelligence._check_domain_age", return_value=(1200, "GoDaddy"))
    @patch("veilux_ng.features.url_intelligence.URLIntelligence._check_threat_intel", return_value=False)
    def test_legitimate_url_low_risk(self, _ti, _age, _ssl):
        report = _analyzer.analyze("https://www.google.com/search?q=test")
        assert report.risk_score < 45
        assert report.risk_level in ("LOW", "MEDIUM")

    @patch("veilux_ng.features.url_intelligence.URLIntelligence._check_ssl", return_value=(False, None, "No SSL found"))
    @patch("veilux_ng.features.url_intelligence.URLIntelligence._check_domain_age", return_value=(2, "Namecheap"))
    @patch("veilux_ng.features.url_intelligence.URLIntelligence._check_threat_intel", return_value=False)
    def test_new_domain_no_ssl_high_risk(self, _ti, _age, _ssl):
        report = _analyzer.analyze("http://g00gle-login.xyz/verify")
        assert report.risk_score >= 45

    @patch("veilux_ng.features.url_intelligence.URLIntelligence._check_ssl", return_value=(True, "DigiCert", None))
    @patch("veilux_ng.features.url_intelligence.URLIntelligence._check_domain_age", return_value=(500, "Registrar"))
    @patch("veilux_ng.features.url_intelligence.URLIntelligence._check_threat_intel", return_value=True)
    def test_threat_intel_hit_is_critical(self, _ti, _age, _ssl):
        report = _analyzer.analyze("https://confirmed-phish.example.com/login")
        assert report.threat_intel_hit is True
        assert report.risk_score >= 40
        assert "CONFIRMED PHISHING" in report.verdict

    @patch("veilux_ng.features.url_intelligence.URLIntelligence._check_ssl", return_value=(True, "CA", None))
    @patch("veilux_ng.features.url_intelligence.URLIntelligence._check_domain_age", return_value=(300, "Reg"))
    @patch("veilux_ng.features.url_intelligence.URLIntelligence._check_threat_intel", return_value=False)
    def test_at_symbol_flagged(self, _ti, _age, _ssl):
        report = _analyzer.analyze("http://legit.com@evil.com/path")
        flags_text = " ".join(report.flags)
        assert "@" in flags_text or "symbol" in flags_text.lower()

    @patch("veilux_ng.features.url_intelligence.URLIntelligence._check_ssl", return_value=(True, "CA", None))
    @patch("veilux_ng.features.url_intelligence.URLIntelligence._check_domain_age", return_value=(300, "Reg"))
    @patch("veilux_ng.features.url_intelligence.URLIntelligence._check_threat_intel", return_value=False)
    def test_brand_impersonation_detected(self, _ti, _age, _ssl):
        report = _analyzer.analyze("https://paypa1.com/login")
        assert report.impersonated_brand is not None

    def test_score_levels_correct(self):
        assert _analyzer._score_to_level(75) == "CRITICAL"
        assert _analyzer._score_to_level(50) == "HIGH"
        assert _analyzer._score_to_level(30) == "MEDIUM"
        assert _analyzer._score_to_level(5)  == "LOW"

    @patch("veilux_ng.features.url_intelligence.URLIntelligence._check_ssl", return_value=(True, "CA", None))
    @patch("veilux_ng.features.url_intelligence.URLIntelligence._check_domain_age", return_value=(300, "Reg"))
    @patch("veilux_ng.features.url_intelligence.URLIntelligence._check_threat_intel", return_value=False)
    def test_verdict_not_definitive_for_heuristic(self, _ti, _age, _ssl):
        """Heuristic scores must not claim confirmed malice without TI hit."""
        report = _analyzer.analyze("http://g00gle-login.xyz/verify")
        assert "CONFIRMED" not in report.verdict

    @patch("veilux_ng.features.url_intelligence.URLIntelligence._check_ssl", return_value=(None, None, None))
    @patch("veilux_ng.features.url_intelligence.URLIntelligence._check_domain_age", return_value=(None, None))
    @patch("veilux_ng.features.url_intelligence.URLIntelligence._check_threat_intel", return_value=False)
    def test_unavailable_checks_do_not_crash(self, _ti, _age, _ssl):
        report = _analyzer.analyze("https://example.com")
        assert report is not None
        assert report.risk_score >= 0
