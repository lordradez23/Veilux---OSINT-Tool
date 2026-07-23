"""
Integration tests — Full VeiluxEngine workflow
These tests make real network calls. Run with: pytest tests/integration/ -v
"""

import pytest
from veilux_ng import VeiluxEngine


@pytest.fixture(scope="module")
def engine():
    return VeiluxEngine()


class TestEngineAutoDetect:
    def test_phone_detected(self, engine):
        assert engine._detect_type("08031234567") == "phone"

    def test_ip_detected(self, engine):
        assert engine._detect_type("8.8.8.8") == "ip"

    def test_domain_detected(self, engine):
        assert engine._detect_type("example.com") == "domain"

    def test_url_detected(self, engine):
        assert engine._detect_type("https://example.com") == "url"

    def test_image_detected(self, engine):
        assert engine._detect_type("https://example.com/photo.jpg") == "image"

    def test_username_fallback(self, engine):
        assert engine._detect_type("lordradeez") == "username"


class TestEngineInvestigate:
    def test_phone_investigation(self, engine):
        report = engine.investigate("08031234567", feature="phone_analysis")
        assert "phone_analysis" in report.results
        assert report.results["phone_analysis"].is_valid is True

    def test_ip_investigation(self, engine):
        from unittest.mock import patch, MagicMock
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "status": "success", "country": "United States", "countryCode": "US",
            "regionName": "California", "city": "Mountain View",
            "isp": "Google LLC", "as": "AS15169", "proxy": False, "hosting": False,
            "lat": 37.4056, "lon": -122.0775, "timezone": "America/Los_Angeles",
        }
        with patch("veilux_ng.features.ip_intelligence.safe_request", return_value=mock_resp):
            report = engine.investigate("8.8.8.8", feature="ip_intelligence")
        assert "ip_intelligence" in report.results
        r = report.results["ip_intelligence"]
        assert r.is_valid is True
        assert r.country == "United States"

    def test_url_shortener(self, engine):
        result = engine.shorten_url("https://www.example.com/test")
        assert result.short_code
        assert result.short_url.startswith("http")

    def test_compliance_report_all_pass(self, engine):
        results = engine.compliance_report()
        assert all(r.is_compliant for r in results)
