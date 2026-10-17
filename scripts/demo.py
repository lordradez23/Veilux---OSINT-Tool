"""
VEILUX-NG Demo Script
Exercises all four intelligence modules with safe, public test data.
Run: python scripts/demo.py
"""

from unittest.mock import patch, MagicMock
from veilux_ng import VeiluxEngine

engine = VeiluxEngine()
DIVIDER = "=" * 60


def section(title: str) -> None:
    print(f"\n{DIVIDER}\n  {title}\n{DIVIDER}")


def run_demo() -> None:
    print(f"\n{DIVIDER}")
    print("  VEILUX-NG v3.0.0 — Module Demo")
    print(DIVIDER)

    # 1. Phone Intelligence
    section("1. Phone Intelligence")
    r = engine.investigate("08031234567", feature="phone_analysis")
    p = r.results.get("phone_analysis")
    if p:
        print(f"  Number    : {p.normalized}")
        print(f"  Valid     : {p.is_valid}")
        print(f"  Network   : {p.network_type}")
        print(f"  Carrier   : {p.carrier_name}")
        print(f"  Region    : {p.region}")
        print(f"  Timestamp : {p.timestamp}")

    # 2. IP Intelligence (mocked — no API key required for demo)
    section("2. IP Intelligence")
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "status": "success", "country": "Nigeria", "countryCode": "NG",
        "regionName": "Lagos", "city": "Lagos", "isp": "MTN Nigeria",
        "as": "AS29465 MTN", "proxy": False, "hosting": False,
        "lat": 6.45, "lon": 3.39, "timezone": "Africa/Lagos",
    }
    with patch("veilux_ng.features.ip_intelligence.safe_request", return_value=mock_resp):
        r = engine.investigate("41.58.0.1", feature="ip_intelligence")
    ip = r.results.get("ip_intelligence")
    if ip:
        print(f"  IP        : {ip.ip}")
        print(f"  Country   : {ip.country}")
        print(f"  City      : {ip.city}")
        print(f"  ISP       : {ip.isp}")
        print(f"  Risk      : {ip.risk_score}/100")
        print(f"  Sources   : {', '.join(ip.data_sources)}")

    # 3. Social Discovery (mocked — avoids live HTTP)
    section("3. Social Discovery")
    found_resp = MagicMock()
    found_resp.status_code = 200
    found_resp.text = "<html>profile page</html>"
    with patch("veilux_ng.features.social_discovery.safe_request", return_value=found_resp):
        r = engine.investigate("torvalds", feature="social_discovery")
    s = r.results.get("social_discovery")
    if s:
        print(f"  Username  : {s.username}")
        print(f"  Found on  : {s.total_found} platform(s)")
        for profile in s.found[:3]:
            print(f"    [+] {profile.platform}: {profile.url}")

    # 4. URL Intelligence
    section("4. URL Intelligence")
    with patch("veilux_ng.features.url_intelligence.URLIntelligence._check_ssl",
               return_value=(False, None, "No SSL found")), \
         patch("veilux_ng.features.url_intelligence.URLIntelligence._check_domain_age",
               return_value=(5, "Namecheap")), \
         patch("veilux_ng.features.url_intelligence.URLIntelligence._check_threat_intel",
               return_value=False):
        r = engine.investigate("http://paypa1.com/login", feature="url_intelligence")
    u = r.results.get("url_intelligence")
    if u:
        print(f"  URL       : {u.url}")
        print(f"  Score     : {u.risk_score}/100")
        print(f"  Level     : {u.risk_level}")
        print(f"  Brand hit : {u.impersonated_brand}")
        print(f"  Verdict   : {u.verdict}")
        for flag in u.flags:
            print(f"    [!] {flag}")

    # Compliance report
    section("Compliance Report (NDPA 2023)")
    for c in engine.compliance_report():
        status = "[OK]" if c.is_compliant else "[X]"
        print(f"  {status} {c.feature:<22} {c.ndpa_section}")

    print(f"\n{DIVIDER}")
    print("  Demo complete.")
    print(DIVIDER)


if __name__ == "__main__":
    run_demo()
