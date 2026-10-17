"""
Unit tests — IP Intelligence
"""

from unittest.mock import MagicMock, patch

import pytest

from veilux_ng.features.ip_intelligence import IPIntelligence, IPReport

_analyzer = IPIntelligence()


def _mock_resp(payload: dict, status: int = 200) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status
    resp.json.return_value = payload
    return resp


class TestValidation:
    def test_invalid_ip_returns_invalid_report(self):
        r = _analyzer.analyze("not-an-ip")
        assert r.is_valid is False
        assert "Invalid" in r.notes

    def test_valid_public_ip(self):
        with patch("veilux_ng.features.ip_intelligence.safe_request", return_value=None):
            r = _analyzer.analyze("8.8.8.8")
        assert r.is_valid is True
        assert r.ip == "8.8.8.8"

    def test_private_ip_flagged(self):
        with patch("veilux_ng.features.ip_intelligence.safe_request", return_value=None):
            r = _analyzer.analyze("192.168.1.1")
        assert r.is_private is True

    def test_loopback_flagged_private(self):
        with patch("veilux_ng.features.ip_intelligence.safe_request", return_value=None):
            r = _analyzer.analyze("127.0.0.1")
        assert r.is_private is True

    def test_ipv6_valid(self):
        with patch("veilux_ng.features.ip_intelligence.safe_request", return_value=None):
            r = _analyzer.analyze("2001:4860:4860::8888")
        assert r.is_valid is True


class TestModuleResultBase:
    def test_module_field(self):
        with patch("veilux_ng.features.ip_intelligence.safe_request", return_value=None):
            r = _analyzer.analyze("8.8.8.8")
        assert r.module == "ip_intelligence"

    def test_input_value_field(self):
        with patch("veilux_ng.features.ip_intelligence.safe_request", return_value=None):
            r = _analyzer.analyze("8.8.8.8")
        assert r.input_value == "8.8.8.8"

    def test_invalid_ip_module_field(self):
        r = _analyzer.analyze("bad-ip")
        assert r.module == "ip_intelligence"


class TestIPinfoProvider:
    def test_ipinfo_populates_geolocation(self):
        payload = {
            "country": "US", "region": "California", "city": "Mountain View",
            "postal": "94043", "timezone": "America/Los_Angeles",
            "org": "AS15169 Google LLC", "loc": "37.4056,-122.0775",
            "hostname": "dns.google",
        }
        with patch("veilux_ng.features.ip_intelligence.safe_request") as mock_req, \
             patch("veilux_ng.features.ip_intelligence.settings") as mock_cfg:
            mock_cfg.IPINFO_TOKEN = "test-token"
            mock_cfg.IPREGISTRY_API_KEY = ""
            mock_cfg.MAXMIND_ACCOUNT_ID = ""
            mock_cfg.MAXMIND_LICENSE_KEY = ""
            mock_cfg.SPUR_API_TOKEN = ""
            mock_req.return_value = _mock_resp(payload)
            r = _analyzer.analyze("8.8.8.8")

        assert r.country == "US"
        assert r.city == "Mountain View"
        assert r.latitude == pytest.approx(37.4056)
        assert "ipinfo" in r.data_sources

    def test_ipinfo_privacy_flags(self):
        payload = {
            "country": "US", "loc": "0,0",
            "privacy": {"vpn": True, "proxy": False, "tor": True, "relay": False, "hosting": True},
        }
        with patch("veilux_ng.features.ip_intelligence.safe_request") as mock_req, \
             patch("veilux_ng.features.ip_intelligence.settings") as mock_cfg:
            mock_cfg.IPINFO_TOKEN = "test-token"
            mock_cfg.IPREGISTRY_API_KEY = ""
            mock_cfg.MAXMIND_ACCOUNT_ID = ""
            mock_cfg.MAXMIND_LICENSE_KEY = ""
            mock_cfg.SPUR_API_TOKEN = ""
            mock_req.return_value = _mock_resp(payload)
            r = _analyzer.analyze("1.2.3.4")

        assert r.is_vpn is True
        assert r.is_tor is True
        assert r.is_hosting is True
        assert r.is_proxy is False


class TestFallbackChain:
    def test_ipapi_fallback_used_when_no_premium_keys(self):
        payload = {
            "status": "success", "country": "Nigeria", "countryCode": "NG",
            "regionName": "Lagos", "city": "Lagos", "isp": "MTN",
            "as": "AS29465 MTN", "proxy": False, "hosting": False,
            "lat": 6.45, "lon": 3.39, "timezone": "Africa/Lagos",
        }
        with patch("veilux_ng.features.ip_intelligence.safe_request",
                   return_value=_mock_resp(payload)), \
             patch("veilux_ng.features.ip_intelligence.settings") as mock_cfg:
            mock_cfg.IPINFO_TOKEN = ""
            mock_cfg.IPREGISTRY_API_KEY = ""
            mock_cfg.MAXMIND_ACCOUNT_ID = ""
            mock_cfg.MAXMIND_LICENSE_KEY = ""
            mock_cfg.SPUR_API_TOKEN = ""
            r = _analyzer.analyze("41.58.0.1")

        assert r.country == "Nigeria"
        assert "ip-api" in r.data_sources

    def test_all_providers_fail_gracefully(self):
        with patch("veilux_ng.features.ip_intelligence.safe_request", return_value=None), \
             patch("veilux_ng.features.ip_intelligence.settings") as mock_cfg:
            mock_cfg.IPINFO_TOKEN = ""
            mock_cfg.IPREGISTRY_API_KEY = ""
            mock_cfg.MAXMIND_ACCOUNT_ID = ""
            mock_cfg.MAXMIND_LICENSE_KEY = ""
            mock_cfg.SPUR_API_TOKEN = ""
            r = _analyzer.analyze("8.8.8.8")

        assert r.is_valid is True
        assert r.country is None
        assert r.data_sources == []


class TestRiskScoring:
    def _report(self, **kwargs) -> IPReport:
        r = IPReport(module="ip_intelligence", input_value="1.2.3.4", ip="1.2.3.4", is_valid=True)
        for k, v in kwargs.items():
            setattr(r, k, v)
        return r

    def test_tor_scores_50(self):
        r = self._report(is_tor=True, country="US")
        IPIntelligence._calculate_risk(r)
        assert r.risk_score >= 50

    def test_vpn_scores_35(self):
        r = self._report(is_vpn=True, country="US")
        IPIntelligence._calculate_risk(r)
        assert r.risk_score >= 35

    def test_score_capped_at_100(self):
        r = self._report(is_tor=True, is_vpn=True, is_proxy=True,
                         is_hosting=True, threat_level="HIGH", country="US")
        IPIntelligence._calculate_risk(r)
        assert r.risk_score == 100

    def test_clean_ip_scores_zero(self):
        r = self._report(country="US")
        IPIntelligence._calculate_risk(r)
        assert r.risk_score == 0

    def test_no_country_adds_10(self):
        r = self._report()
        IPIntelligence._calculate_risk(r)
        assert r.risk_score >= 10
