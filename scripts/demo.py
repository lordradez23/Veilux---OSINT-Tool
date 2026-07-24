"""
VEILUX-NG Demo Script
Exercises all 7 features with safe, public test data.
Run: python scripts/demo.py
"""

from veilux_ng import VeiluxEngine

engine = VeiluxEngine()

DIVIDER = "=" * 60


def section(title: str) -> None:
    print(f"\n{DIVIDER}\n  {title}\n{DIVIDER}")


def run_demo() -> None:
    print(f"\n{DIVIDER}")
    print("  VEILUX-NG v2.0.0 — Feature Demo")
    print(DIVIDER)

    # 1. Phone Analysis
    section("1. Phone Analysis")
    r = engine.investigate("08031234567", feature="phone_analysis")
    p = r.results.get("phone_analysis")
    if p:
        print(f"  Number    : {p.normalized}")
        print(f"  Valid     : {p.is_valid}")
        print(f"  Carrier   : {p.carrier_name}")
        print(f"  Country   : {p.country}")

    # 2. IP Intelligence
    section("2. IP Intelligence")
    r = engine.investigate("8.8.8.8", feature="ip_intelligence")
    ip = r.results.get("ip_intelligence")
    if ip:
        print(f"  IP        : {ip.ip}")
        print(f"  Location  : {ip.city}, {ip.country}")
        print(f"  ISP       : {ip.isp}")
        print(f"  Proxy     : {ip.is_proxy}")
        print(f"  Risk      : {ip.risk_score}/100")

    # 3. Domain Analysis
    section("3. Domain Analysis")
    r = engine.investigate("example.com", feature="domain_analysis")
    d = r.results.get("domain_analysis")
    if d:
        print(f"  Domain    : {d.domain}")
        print(f"  Registrar : {d.registrar}")
        print(f"  Age       : {d.age_days} days")
        print(f"  SSL Valid : {d.ssl.valid if d.ssl else 'N/A'}")
        print(f"  SSL CA    : {d.ssl.issuer if d.ssl else 'N/A'}")

    # 4. Phishing Detection
    section("4. Phishing Detection")
    r = engine.investigate("http://paypa1.com/login", feature="phishing_detector")
    ph = r.results.get("phishing_detector")
    if ph:
        print(f"  URL       : {ph.url}")
        print(f"  Score     : {ph.risk_score}/100")
        print(f"  Level     : {ph.risk_level}")
        print(f"  Brand hit : {ph.impersonated_brand}")
        print(f"  Verdict   : {ph.verdict}")
        for flag in ph.flags:
            print(f"    ⚑ {flag}")

    # 5. Social Discovery
    section("5. Social Discovery")
    r = engine.investigate("torvalds", feature="social_discovery")
    s = r.results.get("social_discovery")
    if s:
        print(f"  Username  : {s.username}")
        print(f"  Found on  : {s.total_found} platform(s)")
        for profile in s.found:
            print(f"    [+] {profile.platform}: {profile.url}")

    # 6. URL Shortener
    section("6. URL Shortener")
    result = engine.shorten_url("https://www.example.com/very/long/path?query=value", campaign="demo")
    print(f"  Long URL  : {result.long_url}")
    print(f"  Short URL : {result.short_url}")
    print(f"  Code      : {result.short_code}")
    print(f"  Campaign  : {result.campaign}")

    # 7. Image Analysis
    section("7. Image Analysis")
    r = engine.investigate(
        "https://upload.wikimedia.org/wikipedia/commons/thumb/4/47/PNG_transparency_demonstration_1.png/280px-PNG_transparency_demonstration_1.png",
        feature="image_analysis",
    )
    img = r.results.get("image_analysis")
    if img:
        print(f"  Format    : {img.format}")
        print(f"  Size      : {img.width}x{img.height}px")
        print(f"  File size : {img.file_size_kb} KB")
        print(f"  GPS       : {img.gps or 'None embedded'}")
        for engine_name, link in img.reverse_search_links.items():
            print(f"  {engine_name:8}: {link}")

    # Compliance report
    section("Compliance Report (NDPA 2023)")
    for c in engine.compliance_report():
        status = "✅" if c.is_compliant else "❌"
        print(f"  {status} {c.feature:<22} {c.ndpa_section}")

    print(f"\n{DIVIDER}")
    print("  Demo complete.")
    print(DIVIDER)


if __name__ == "__main__":
    run_demo()
