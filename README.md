# VEILUX-NG — Integrated OSINT Framework

[![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue?style=flat-square)](https://github.com/lordradez23/Veilux---OSINT-Tool)
[![License](https://img.shields.io/github/license/lordradez23/Veilux---OSINT-Tool?style=flat-square)](LICENSE)

**Version 3.0.0 | By Lordradeez.exe | NDPA 2023 Compliant**

```
██╗   ██╗███████╗██╗██╗     ██╗   ██╗██╗  ██╗     /\___/\
██║   ██║██╔════╝██║██║     ██║   ██║╚██╗██╔╝    (@ @)
██║   ██║█████╗  ██║██║     ██║   ██║ ╚███╔╝      )===(
╚██╗ ██╔╝██╔══╝  ██║██║     ██║   ██║ ██╔██╗     /|   |\
 ╚████╔╝ ███████╗██║███████╗╚██████╔╝██╔╝ ██╗   / | | | \
  ╚═══╝  ╚══════╝╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝  *  * *  *
```

> Modular, legally compliant OSINT reconnaissance across four intelligence domains.

---

## Modules

| # | Module | Input | Description |
|---|--------|-------|-------------|
| 1 | Phone Intelligence | Nigerian phone number | Carrier, region, network type from NCC public prefix tables |
| 2 | IP Intelligence | IPv4 or IPv6 address | Geolocation, ISP, ASN, proxy/VPN/Tor detection |
| 3 | Social Discovery | Username | Public profile search across 15 platforms |
| 4 | URL Intelligence | URL | Phishing indicators, brand impersonation, threat intelligence |

---

## Installation

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt

# Optional: configure API keys for enhanced IP intelligence
copy config\.env.example config\.env
```

---

## Quick Start

```python
from veilux_ng import VeiluxEngine

engine = VeiluxEngine()

# Auto-detect input type and run the appropriate module
report = engine.investigate("08031234567")
print(report.results["phone_analysis"].carrier_name)

# Explicit module selection
report = engine.investigate("8.8.8.8", feature="ip_intelligence")
print(report.results["ip_intelligence"].country)

# URL intelligence
report = engine.investigate("https://paypa1.com/login", feature="url_intelligence")
print(report.results["url_intelligence"].risk_level)  # HIGH or CRITICAL
```

---

## CLI Usage

```powershell
# Interactive menu
python main.py

# Single target (auto-detect)
python main.py 08031234567

# Explicit module
python main.py 8.8.8.8 --feature ip_intelligence

# Save report
python main.py https://example.com --feature url_intelligence --output report.json

# Batch mode
python main.py --batch targets.txt --output reports/
```

---

## Project Structure

```
├── config/
│   ├── settings.py        # Environment-based configuration
│   └── .env.example       # API key template
├── docs/
│   ├── API.md             # Full API reference
│   └── LEGAL.md           # NDPA 2023 compliance guide
├── scripts/
│   └── demo.py            # Runs all four modules with safe test data
├── tests/
│   ├── integration/
│   │   └── test_engine_workflow.py
│   └── unit/
│       ├── test_utils/
│       │   ├── test_helpers.py
│       │   └── test_validators.py
│       ├── test_phone.py
│       ├── test_ip.py
│       ├── test_social.py
│       └── test_url_intelligence.py
└── veilux_ng/
    ├── cli/
    │   ├── commands.py    # Interactive menu + argparse CLI
    │   └── formatters.py  # Colour terminal output
    ├── core/
    │   ├── engine.py      # VeiluxEngine — central orchestrator
    │   ├── compliance.py  # NDPA 2023 compliance checks
    │   ├── result.py      # ModuleResult shared base dataclass
    │   ├── exceptions.py  # Custom exception hierarchy
    │   ├── reporter.py    # JSON / TXT export
    │   └── logger.py      # Structured logging
    ├── features/
    │   ├── phone_analysis.py
    │   ├── ip_intelligence.py
    │   ├── social_discovery.py
    │   └── url_intelligence.py
    ├── utils/
    │   ├── validators.py  # Input sanitisation
    │   ├── helpers.py     # Shared utilities
    │   └── constants.py   # Nigerian carrier/state maps, brand list
    ├── main.py            # CLI entry point
    └── version.py         # Version: 3.0.0
```

---

## Running Tests

```powershell
# All tests
python -m pytest tests/ -v

# Unit tests only
python -m pytest tests/unit/ -v

# Integration tests only
python -m pytest tests/integration/ -v
```

---

## Environment Variables

See `config/.env.example`. All keys are optional — the system degrades gracefully without them.

| Variable | Module | Purpose |
|---|---|---|
| `IPINFO_TOKEN` | IP Intelligence | Geolocation, company, ASN, privacy |
| `IPREGISTRY_API_KEY` | IP Intelligence | Threat levels, carrier data |
| `MAXMIND_ACCOUNT_ID` / `MAXMIND_LICENSE_KEY` | IP Intelligence | GeoIP2 Insights |
| `SPUR_API_TOKEN` | IP Intelligence | VPN/proxy/residential proxy context |

---

## Legal

All modules operate exclusively on **publicly available data** under NDPA 2023 Section 31.
No personal data is stored. See [LEGAL.md](docs/LEGAL.md).

---

## Breaking Changes from v2.0.0

- `phishing_detector` feature key renamed to `url_intelligence`
- `domain_analysis`, `image_analysis`, `url_shortener` modules removed
- `engine.shorten_url()` removed
- Tests consolidated from `veilux_ng/tests/` into `tests/`
- `Pillow` and `dnspython` removed from dependencies

---

*Powered by Lordradeez.exe*
