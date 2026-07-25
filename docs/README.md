# VEILUX-NG — Next Generation Nigerian OSINT Framework
**Version 2.0.0 | By Lordradeez.exe | NDPA 2023 Compliant**

```
██╗   ██╗███████╗██╗██╗     ██╗   ██╗██╗  ██╗     /\___/\
██║   ██║██╔════╝██║██║     ██║   ██║╚██╗██╔╝    (@ @)
██║   ██║█████╗  ██║██║     ██║   ██║ ╚███╔╝      )===(
╚██╗ ██╔╝██╔══╝  ██║██║     ██║   ██║ ██╔██╗     /|   |\
 ╚████╔╝ ███████╗██║███████╗╚██████╔╝██╔╝ ██╗   / | | | \
  ╚═══╝  ╚══════╝╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝  *  * *  *
```

> Stealthy, modular, legally compliant OSINT reconnaissance for the Nigerian digital landscape.

---

## Features

| # | Module | Description | Auth Required |
|---|--------|-------------|---------------|
| 1 | URL Shortener | Shorten URLs + track anonymised click analytics | None |
| 2 | Phishing Detector | Score URLs for phishing risk (0–100) | None |
| 3 | Social Discovery | Find public profiles across 15 platforms | None |
| 4 | Phone Analysis | Nigerian carrier/state from NCC prefix tables | None |
| 5 | Domain Analysis | WHOIS + DNS + SSL + hosting intelligence | None |
| 6 | Image Analysis | EXIF metadata + GPS + reverse search links | None |
| 7 | IP Intelligence | Geolocation + ISP + ASN + proxy detection | None |

---

## Installation

```powershell
# 1. Clone / download the project
cd Veilux---OSINT-Tool-main

# 2. Create and activate virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure environment (optional — all features work without keys)
copy veilux_ng\config\.env.example veilux_ng\config\.env
# Edit .env to add optional API keys
```

**Requirements:** Python 3.10+, internet connection for API lookups.

---

## Quick Start

```python
from veilux_ng import VeiluxEngine

engine = VeiluxEngine()

# Auto-detect identifier type and run applicable modules
report = engine.investigate("08031234567")
print(report.results["phone_analysis"])

# Run a specific feature
report = engine.investigate("https://suspicious-login.xyz", feature="phishing_detector")
print(report.results["phishing_detector"].risk_level)   # CRITICAL / HIGH / MEDIUM / LOW

# Shorten a URL
result = engine.shorten_url("https://very-long-url.com/path?query=value", campaign="promo")
print(result.short_url)   # http://veilux.local/aBcDeFgH

# Get click analytics
analytics = engine.url_shortener.get_analytics("aBcDeFgH")
print(analytics.total_clicks, analytics.by_country)
```

---

## Usage Examples

### Phone Analysis
```python
report = engine.investigate("08031234567", feature="phone_analysis")
r = report.results["phone_analysis"]
print(r.carrier_name)   # MTN
print(r.normalized)     # +2348031234567
print(r.scam_reports)   # 0 (or count from public DB)
```

### Phishing Detection
```python
report = engine.investigate("http://paypa1.com/login", feature="phishing_detector")
r = report.results["phishing_detector"]
print(r.risk_score)          # e.g. 75
print(r.risk_level)          # CRITICAL
print(r.impersonated_brand)  # paypal
print(r.flags)               # list of risk indicators
```

### Social Discovery
```python
report = engine.investigate("lordradeez", feature="social_discovery")
r = report.results["social_discovery"]
for profile in r.found:
    print(f"[+] {profile.platform}: {profile.url}")
```

### Domain Analysis
```python
report = engine.investigate("example.com", feature="domain_analysis")
r = report.results["domain_analysis"]
print(r.registrar, r.age_days)
print(r.dns_records)
print(r.ssl.issuer, r.ssl.days_until_expiry)
```

### Image Analysis
```python
report = engine.investigate(
    "https://example.com/photo.jpg", feature="image_analysis"
)
r = report.results["image_analysis"]
print(r.camera_make, r.camera_model)
if r.gps:
    print(r.gps.maps_url)
print(r.reverse_search_links["Google"])
```

### IP Intelligence
```python
report = engine.investigate("8.8.8.8", feature="ip_intelligence")
r = report.results["ip_intelligence"]
print(r.country, r.city, r.isp)
print(r.is_proxy, r.risk_score)
```

---

## Running Tests

```powershell
python -m pytest veilux_ng/tests/ -v
```

---

## Project Structure

```
veilux_ng/
├── core/
│   ├── engine.py          # Main orchestrator — VeiluxEngine
│   ├── compliance.py      # NDPA 2023 compliance checks
│   └── logger.py          # Structured logging
├── features/
│   ├── url_shortener.py
│   ├── phishing_detector.py
│   ├── social_discovery.py
│   ├── phone_analysis.py
│   ├── domain_analysis.py
│   ├── image_analysis.py
│   └── ip_intelligence.py
├── utils/
│   ├── validators.py      # Input sanitisation
│   ├── helpers.py         # Shared utilities
│   └── constants.py       # Nigerian carrier/state maps, brand list
├── config/
│   ├── settings.py
│   └── .env.example
└── tests/
    ├── test_phone.py
    ├── test_social.py
    └── test_phishing.py
```

---

## Legal & Compliance

All features operate exclusively on **publicly available data**.
See [docs/LEGAL.md](docs/LEGAL.md) for the full NDPA 2023 compliance breakdown.

**This tool is intended for:**
- Cybersecurity research and education
- Fraud investigation using public records
- Final year academic projects
- Ethical OSINT reconnaissance

**This tool must NOT be used for:**
- Stalking, harassment, or surveillance of individuals
- Accessing private accounts or non-public data
- Any activity that violates Nigerian law or NDPA 2023

---

*Powered by Lordradeez.exe*
