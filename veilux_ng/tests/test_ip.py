"""
Unit tests — IP Intelligence (multi-provider, risk scoring, field mapping)
"""

from unittest.mock import MagicMock, patch

import pytest

from veilux_ng.features.ip_intelligence import IPIntelligence, IPReport

_analyzer = IPIntelligence()


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------
class TestValidation:
    def test_invalid_ip_returns_invalid_report(self):
        r = _analyzer.analyze("not-an-ip")
        assert r.is_valid is False
        assert "Invalid" in r.notes

    def test_valid_public_ip_is_valid(self):
        with patch("veilux_ng.features.ip_intelligence.safe_request") as mock_req:
            mock_req.return_value = None  # all providers fail gracefully
            r = _analyzer.analyze("8.8.8.8")
        assert r.is_valid is True
        assert r.ip == "8.8.8.8"

    def test_private_ip_flagged(self):
        with patch("veilux_ng.features.ip_intelligence.safe_request") as mock_req:
            mock_req.return_value = None
            r = _analyzer.analyze("192.168.1.1")
        assert r.is_private is True

    def test_loopback_flagged_private(self):
        with patch("veilux_ng.features.ip_intelligence.safe_request") as mock_req:
            mock_req.return_value = None
            r = _analyzer.analyze("127.0.0.1")
        assert r.is_private is True


# ---------------------------------------------------------------------------
# IPinfo provider
# ---------------------------------------------------------------------------
class TestIPinfoProvider:
    def _mock_resp(self, payload: dict, status: int = 200):
        resp = MagicMock()
        resp.status_code = status
        resp.json.return_value = payload
        return resp

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
            mock_req.return_value = self._mock_resp(payload)
            r = _analyzer.analyze("8.8.8.8")

        assert r.country == "US"
        assert r.city == "Mountain View"
        assert r.latitude == pytest.approx(37.4056)
        assert r.longitude == pytest.approx(-122.0775)
        assert r.hostname == "dns.google"
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
            mock_req.return_value = self._mock_resp(payload)
            r = _analyzer.analyze("1.2.3.4")

        assert r.is_vpn is True
        assert r.is_tor is True
        assert r.is_hosting is True
        assert r.is_proxy is False

    def test_ipinfo_company_fields(self):
        payload = {
            "country": "US", "loc": "0,0",
            "company": {"name": "Google LLC", "domain": "google.com", "type": "hosting"},
        }
        with patch("veilux_ng.features.ip_intelligence.safe_request") as mock_req, \
             patch("veilux_ng.features.ip_intelligence.settings") as mock_cfg:
            mock_cfg.IPINFO_TOKEN = "test-token"
            mock_cfg.IPREGISTRY_API_KEY = ""
            mock_cfg.MAXMIND_ACCOUNT_ID = ""
            mock_cfg.MAXMIND_LICENSE_KEY = ""
            mock_cfg.SPUR_API_TOKEN = ""
            mock_req.return_value = self._mock_resp(payload)
            r = _analyzer.analyze("8.8.8.8")

        assert r.company_name == "Google LLC"
        assert r.company_domain == "google.com"
        assert r.company_type == "hosting"


# ---------------------------------------------------------------------------
# Ipregistry provider
# ---------------------------------------------------------------------------
class TestIpregistryProvider:
    def _mock_resp(self, payload: dict):
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = payload
        return resp

    def test_ipregistry_threat_level_and_carrier(self):
        payload = {
            "location": {
                "country": {"name": "Nigeria", "code": "NG"},
                "region": {"name": "Lagos"},
                "city": "Lagos",
                "latitude": 6.45, "longitude": 3.39,
                "time_zone": {"id": "Africa/Lagos"},
            },
            "connection": {"asn": 29465, "organization": "MTN Nigeria", "isp": "MTN"},
            "carrier": {"name": "MTN Nigeria"},
            "security": {
                "is_vpn": False, "is_proxy": True, "is_tor": False,
                "is_datacenter": False, "threat_level": "MEDIUM",
                "is_bogon": False, "is_abuser": True, "is_attacker": False, "is_anonymous": False,
            },
        }
        with patch("veilux_ng.features.ip_intelligence.safe_request") as mock_req, \
             patch("veilux_ng.features.ip_intelligence.settings") as mock_cfg:
            mock_cfg.IPINFO_TOKEN = ""
            mock_cfg.IPREGISTRY_API_KEY = "test-key"
            mock_cfg.MAXMIND_ACCOUNT_ID = ""
            mock_cfg.MAXMIND_LICENSE_KEY = ""
            mock_cfg.SPUR_API_TOKEN = ""
            mock_req.return_value = self._mock_resp(payload)
            r = _analyzer.analyze("41.58.0.1")

        assert r.country == "Nigeria"
        assert r.carrier == "MTN Nigeria"
        assert r.threat_level == "MEDIUM"
        assert r.is_proxy is True
        assert "Known abuser" in r.threat_types
        assert "ipregistry" in r.data_sources


# ---------------------------------------------------------------------------
# Spur provider
# ---------------------------------------------------------------------------
class TestSpurProvider:
    def test_spur_tunnel_detection(self):
        payload = {
            "tunnels": [{"type": "VPN"}, {"type": "RESIDENTIAL"}],
            "infrastructure": "HOSTING",
        }
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = payload

        # Call order with only SPUR_API_TOKEN set:
        #   1. _query_spur  (returns payload)
        #   2. _query_ipapi (country still None after spur → fallback runs)
        #   3. _query_ipwhois (second fallback)
        ipapi_fail = MagicMock()
        ipapi_fail.status_code = 200
        ipapi_fail.json.return_value = {"status": "fail"}

        ipwhois_resp = MagicMock()
        ipwhois_resp.status_code = 200
        ipwhois_resp.json.return_value = {"success": True, "country": "US", "country_code": "US",
                                          "connection": {}, "timezone": {}}

        with patch("veilux_ng.features.ip_intelligence.safe_request") as mock_req, \
             patch("veilux_ng.features.ip_intelligence.settings") as mock_cfg:
            mock_cfg.IPINFO_TOKEN = ""
            mock_cfg.IPREGISTRY_API_KEY = ""
            mock_cfg.MAXMIND_ACCOUNT_ID = ""
            mock_cfg.MAXMIND_LICENSE_KEY = ""
            mock_cfg.SPUR_API_TOKEN = "spur-token"
            mock_req.side_effect = [resp, ipapi_fail, ipwhois_resp]
            r = _analyzer.analyze("5.5.5.5")

        assert "VPN" in r.spur_tunnels
        assert "RESIDENTIAL" in r.spur_tunnels
        assert r.spur_infrastructure == "HOSTING"
        assert r.is_vpn is True
        assert "spur" in r.data_sources

    def test_spur_tor_sets_is_tor(self):
        payload = {"tunnels": [{"type": "TOR"}], "infrastructure": "TOR"}
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = payload

        ipapi_fail = MagicMock()
        ipapi_fail.status_code = 200
        ipapi_fail.json.return_value = {"status": "fail"}

        ipwhois_resp = MagicMock()
        ipwhois_resp.status_code = 200
        ipwhois_resp.json.return_value = {"success": True, "country": "US", "country_code": "US",
                                          "connection": {}, "timezone": {}}

        with patch("veilux_ng.features.ip_intelligence.safe_request") as mock_req, \
             patch("veilux_ng.features.ip_intelligence.settings") as mock_cfg:
            mock_cfg.IPINFO_TOKEN = ""
            mock_cfg.IPREGISTRY_API_KEY = ""
            mock_cfg.MAXMIND_ACCOUNT_ID = ""
            mock_cfg.MAXMIND_LICENSE_KEY = ""
            mock_cfg.SPUR_API_TOKEN = "spur-token"
            mock_req.side_effect = [resp, ipapi_fail, ipwhois_resp]
            r = _analyzer.analyze("5.5.5.5")

        assert r.is_tor is True


# ---------------------------------------------------------------------------
# Risk scoring
# ---------------------------------------------------------------------------
class TestRiskScoring:
    def _report(self, **kwargs) -> IPReport:
        r = IPReport(ip="1.2.3.4", is_valid=True)
        for k, v in kwargs.items():
            setattr(r, k, v)
        return r

    def test_tor_scores_50(self):
        r = self._report(is_tor=True, country="US")
        IPIntelligence._calculate_risk(r)
        assert r.risk_score >= 50
        assert any("Tor" in f for f in r.risk_flags)

    def test_vpn_scores_35(self):
        r = self._report(is_vpn=True, country="US")
        IPIntelligence._calculate_risk(r)
        assert r.risk_score >= 35
        assert any("VPN" in f for f in r.risk_flags)

    def test_proxy_scores_30(self):
        r = self._report(is_proxy=True, country="US")
        IPIntelligence._calculate_risk(r)
        assert r.risk_score >= 30

    def test_high_threat_level_adds_30(self):
        r = self._report(threat_level="HIGH", country="US")
        IPIntelligence._calculate_risk(r)
        assert r.risk_score >= 30
        assert any("HIGH" in f for f in r.risk_flags)

    def test_medium_threat_level_adds_15(self):
        r = self._report(threat_level="MEDIUM", country="US")
        IPIntelligence._calculate_risk(r)
        assert r.risk_score >= 15

    def test_score_capped_at_100(self):
        r = self._report(
            is_tor=True, is_vpn=True, is_proxy=True, is_hosting=True,
            threat_level="HIGH", country="US",
        )
        IPIntelligence._calculate_risk(r)
        assert r.risk_score == 100

    def test_clean_ip_scores_zero(self):
        r = self._report(country="US")
        IPIntelligence._calculate_risk(r)
        assert r.risk_score == 0
        assert r.risk_flags == []

    def test_no_country_adds_10(self):
        r = self._report()
        IPIntelligence._calculate_risk(r)
        assert r.risk_score >= 10
        assert any("Geolocation" in f for f in r.risk_flags)


# ---------------------------------------------------------------------------
# Fallback chain — free providers fill gaps
# ---------------------------------------------------------------------------
class TestFallbackChain:
    def test_ipapi_fallback_used_when_no_premium_keys(self):
        ipapi_payload = {
            "status": "success", "country": "Nigeria", "countryCode": "NG",
            "regionName": "Lagos", "city": "Lagos", "isp": "MTN",
            "as": "AS29465 MTN", "proxy": False, "hosting": False,
            "lat": 6.45, "lon": 3.39, "timezone": "Africa/Lagos",
        }
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = ipapi_payload

        with patch("veilux_ng.features.ip_intelligence.safe_request", return_value=resp), \
             patch("veilux_ng.features.ip_intelligence.settings") as mock_cfg:
            mock_cfg.IPINFO_TOKEN = ""
            mock_cfg.IPREGISTRY_API_KEY = ""
            mock_cfg.MAXMIND_ACCOUNT_ID = ""
            mock_cfg.MAXMIND_LICENSE_KEY = ""
            mock_cfg.SPUR_API_TOKEN = ""
            r = _analyzer.analyze("41.58.0.1")

        assert r.country == "Nigeria"
        assert "ip-api" in r.data_sources

    def test_ipwhois_fallback_when_ipapi_fails(self):
        ipwhois_payload = {
            "success": True, "country": "Nigeria", "country_code": "NG",
            "region": "Lagos", "city": "Lagos",
            "connection": {"isp": "Airtel", "asn": 36873},
            "timezone": {"id": "Africa/Lagos"},
            "latitude": 6.45, "longitude": 3.39,
        }
        ipapi_fail = MagicMock()
        ipapi_fail.status_code = 200
        ipapi_fail.json.return_value = {"status": "fail"}

        ipwhois_resp = MagicMock()
        ipwhois_resp.status_code = 200
        ipwhois_resp.json.return_value = ipwhois_payload

        with patch("veilux_ng.features.ip_intelligence.safe_request",
                   side_effect=[ipapi_fail, ipwhois_resp]), \
             patch("veilux_ng.features.ip_intelligence.settings") as mock_cfg:
            mock_cfg.IPINFO_TOKEN = ""
            mock_cfg.IPREGISTRY_API_KEY = ""
            mock_cfg.MAXMIND_ACCOUNT_ID = ""
            mock_cfg.MAXMIND_LICENSE_KEY = ""
            mock_cfg.SPUR_API_TOKEN = ""
            r = _analyzer.analyze("41.58.0.1")

        assert r.country == "Nigeria"
        assert "ipwho.is" in r.data_sources
