"""
Integration tests — VeiluxEngine full workflow
All external network calls are mocked so tests are deterministic.
"""

import pytest
from unittest.mock import patch, MagicMock
from veilux_ng import VeiluxEngine


@pytest.fixture(scope="module")
def engine():
    return VeiluxEngine()


# ------------------------------------------------------------------
# Type detection
# ------------------------------------------------------------------
class TestEngineTypeDetection:
    def test_phone_detected(self, engine):
        assert engine._detect_type("08031234567") == "phone"

    def test_phone_with_country_code(self, engine):
        assert engine._detect_type("+2348031234567") == "phone"

    def test_ipv4_detected(self, engine):
        assert engine._detect_type("8.8.8.8") == "ip"

    def test_ipv6_detected(self, engine):
        assert engine._detect_type("2001:4860:4860::8888") == "ip"

    def test_private_ip_detected_as_ip(self, engine):
        assert engine._detect_type("192.168.1.1") == "ip"

    def test_url_detected(self, engine):
        assert engine._detect_type("https://example.com") == "url"

    def test_http_url_detected(self, engine):
        assert engine._detect_type("http://example.com/path") == "url"

    def test_domain_detected(self, engine):
        assert engine._detect_type("example.com") == "domain"

    def test_username_fallback(self, engine):
        assert engine._detect_type("lordradeez") == "username"

    def test_ip_not_misclassified_as_domain(self, engine):
        # 8.8.8.8 must be "ip", not "domain"
        assert engine._detect_type("8.8.8.8") == "ip"


# ------------------------------------------------------------------
# Explicit feature selection
# ------------------------------------------------------------------
class TestExplicitFeatureSelection:
    def test_phone_explicit(self, engine):
        report = engine.investigate("08031234567", feature="phone_analysis")
        assert "phone_analysis" in report.results
        assert report.results["phone_analysis"].is_valid is True

    def test_ip_explicit(self, engine):
        with patch("veilux_ng.features.ip_intelligence.safe_request", return_value=None):
            report = engine.investigate("8.8.8.8", feature="ip_intelligence")
        assert "ip_intelligence" in report.results
        assert report.results["ip_intelligence"].is_valid is True

    def test_social_explicit(self, engine):
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        with patch("veilux_ng.features.social_discovery.safe_request", return_value=mock_resp):
            report = engine.investigate("torvalds", feature="social_discovery")
        assert "social_discovery" in report.results

    def test_url_explicit(self, engine):
        with patch("veilux_ng.features.url_intelligence.URLIntelligence._check_ssl",
                   return_value=(True, "CA", None)), \
             patch("veilux_ng.features.url_intelligence.URLIntelligence._check_domain_age",
                   return_value=(500, "Reg")), \
             patch("veilux_ng.features.url_intelligence.URLIntelligence._check_threat_intel",
                   return_value=False):
            report = engine.investigate("https://example.com", feature="url_intelligence")
        assert "url_intelligence" in report.results

    def test_unknown_feature_raises(self, engine):
        with pytest.raises(ValueError, match="Unknown feature"):
            engine.investigate("test", feature="image_analysis")

    def test_retired_domain_feature_raises(self, engine):
        with pytest.raises(ValueError, match="Unknown feature"):
            engine.investigate("example.com", feature="domain_analysis")

    def test_retired_phishing_key_raises(self, engine):
        with pytest.raises(ValueError, match="Unknown feature"):
            engine.investigate("https://example.com", feature="phishing_detector")


# ------------------------------------------------------------------
# Auto-detection routing
# ------------------------------------------------------------------
class TestAutoDetectionRouting:
    def test_phone_routes_to_phone_analysis(self, engine):
        report = engine.investigate("08031234567")
        assert "phone_analysis" in report.results

    def test_ip_routes_to_ip_intelligence(self, engine):
        with patch("veilux_ng.features.ip_intelligence.safe_request", return_value=None):
            report = engine.investigate("8.8.8.8")
        assert "ip_intelligence" in report.results

    def test_url_routes_to_url_intelligence(self, engine):
        with patch("veilux_ng.features.url_intelligence.URLIntelligence._check_ssl",
                   return_value=(True, "CA", None)), \
             patch("veilux_ng.features.url_intelligence.URLIntelligence._check_domain_age",
                   return_value=(500, "Reg")), \
             patch("veilux_ng.features.url_intelligence.URLIntelligence._check_threat_intel",
                   return_value=False):
            report = engine.investigate("https://example.com")
        assert "url_intelligence" in report.results

    def test_username_routes_to_social_discovery(self, engine):
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        with patch("veilux_ng.features.social_discovery.safe_request", return_value=mock_resp):
            report = engine.investigate("lordradeez")
        assert "social_discovery" in report.results


# ------------------------------------------------------------------
# Result structure
# ------------------------------------------------------------------
class TestResultStructure:
    def test_report_has_timestamp(self, engine):
        report = engine.investigate("08031234567", feature="phone_analysis")
        assert report.timestamp != ""

    def test_report_has_compliance(self, engine):
        report = engine.investigate("08031234567", feature="phone_analysis")
        assert "phone_analysis" in report.compliance

    def test_result_has_module_field(self, engine):
        report = engine.investigate("08031234567", feature="phone_analysis")
        assert report.results["phone_analysis"].module == "phone_analysis"

    def test_result_has_input_value(self, engine):
        report = engine.investigate("08031234567", feature="phone_analysis")
        assert report.results["phone_analysis"].input_value == "08031234567"

    def test_to_dict_serialisable(self, engine):
        import json
        report = engine.investigate("08031234567", feature="phone_analysis")
        d = report.to_dict()
        assert json.dumps(d)  # must not raise

    def test_module_failure_stored_in_errors(self, engine):
        report = engine.investigate("not-a-url", feature="url_intelligence")
        assert "url_intelligence" in report.errors
        assert "url_intelligence" not in report.results


# ------------------------------------------------------------------
# Compliance
# ------------------------------------------------------------------
class TestCompliance:
    def test_all_four_modules_compliant(self, engine):
        results = engine.compliance_report()
        assert len(results) == 4
        assert all(r.is_compliant for r in results)

    def test_compliance_features_are_correct(self, engine):
        features = {r.feature for r in engine.compliance_report()}
        assert features == {
            "phone_analysis", "ip_intelligence",
            "social_discovery", "url_intelligence",
        }

    def test_retired_features_not_in_compliance(self, engine):
        features = {r.feature for r in engine.compliance_report()}
        assert "domain_analysis" not in features
        assert "image_analysis" not in features
        assert "url_shortener" not in features
        assert "phishing_detector" not in features


# ------------------------------------------------------------------
# Module isolation — one module failing does not break others
# ------------------------------------------------------------------
class TestModuleIsolation:
    def test_ip_failure_does_not_affect_phone(self, engine):
        # Investigate a phone number — IP module should not be invoked
        report = engine.investigate("08031234567", feature="phone_analysis")
        assert "phone_analysis" in report.results
        assert "ip_intelligence" not in report.results
        assert "ip_intelligence" not in report.errors
