# VEILUX-NG — Next Generation Nigerian OSINT Framework

[![Build Matrix](https://img.shields.io/github/actions/workflow/status/lordradez23/Veilux---OSINT-Tool/tests.yml?branch=main&label=Build%20Matrix&style=flat-square)](https://github.com/lordradez23/Veilux---OSINT-Tool/actions)
[![Python Matrix](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue?style=flat-square)](https://github.com/lordradez23/Veilux---OSINT-Tool)
[![GitHub Stars](https://img.shields.io/github/stars/lordradez23/Veilux---OSINT-Tool?style=flat-square&logo=github)](https://github.com/lordradez23/Veilux---OSINT-Tool/stargazers)
[![GitHub Forks](https://img.shields.io/github/forks/lordradez23/Veilux---OSINT-Tool?style=flat-square&logo=github)](https://github.com/lordradez23/Veilux---OSINT-Tool/network/members)
[![License](https://img.shields.io/github/license/lordradez23/Veilux---OSINT-Tool?style=flat-square)](LICENSE)

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
| 1 | URL Shortener | Shorten URLs + anonymised click analytics | None |
| 2 | Phishing Detector | Risk-score URLs 0–100 across 11 indicators | None |
| 3 | Social Discovery | Find public profiles across 15 platforms | None |
| 4 | Phone Analysis | Nigerian carrier/state from NCC prefix tables | None |
| 5 | Domain Analysis | WHOIS + DNS + SSL + hosting intelligence | None |
| 6 | Image Analysis | EXIF metadata + GPS + reverse search links | None |
| 7 | IP Intelligence | Geolocation + ISP + ASN + proxy detection | None |

---

## Installation

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt

# Optional: copy and configure environment variables
copy config\.env.example config\.env
```

---

## Quick Start

```python
from veilux_ng import VeiluxEngine

engine = VeiluxEngine()

# Auto-detect type and run applicable modules
report = engine.investigate("08031234567")
print(report.results["phone_analysis"])

# Force a specific feature
report = engine.investigate("https://paypa1.com/login", feature="phishing_detector")
print(report.results["phishing_detector"].risk_level)  # HIGH or CRITICAL

# Shorten a URL
result = engine.shorten_url("https://long-url.com/path")
print(result.short_url)
```

---

## Project Structure

```
├── config/
│   ├── settings.py        # Environment-based configuration
│   └── .env.example       # Template for API keys and settings
├── docs/
│   ├── API.md             # Full API reference
│   ├── LEGAL.md           # NDPA 2023 compliance guide
│   └── README.md          # Extended documentation
├── scripts/
│   └── demo.py            # Runs all 7 features with safe test data
├── tests/
│   ├── integration/
│   │   └── test_full_workflow.py
│   ├── unit/
│   │   └── test_utils/
│   │       ├── test_helpers.py
│   │       └── test_validators.py
│   └── conftest.py
└── veilux_ng/
    ├── cli/
    │   ├── commands.py    # Interactive menu + argparse CLI
    │   └── formatters.py  # Colour terminal output
    ├── core/
    │   ├── engine.py      # VeiluxEngine — main orchestrator
    │   ├── compliance.py  # NDPA 2023 compliance checks
    │   ├── exceptions.py  # Custom exception hierarchy
    │   └── logger.py      # Structured logging
    ├── features/
    │   ├── url_shortener.py
    │   ├── phishing_detector.py
    │   ├── social_discovery.py
    │   ├── phone_analysis.py
    │   ├── domain_analysis.py
    │   ├── image_analysis.py
    │   └── ip_intelligence.py
    ├── tests/
    │   ├── test_phone.py
    │   ├── test_social.py
    │   └── test_phishing.py
    ├── utils/
    │   ├── validators.py  # Input sanitisation
    │   ├── helpers.py     # Shared utilities
    │   └── constants.py   # Nigerian carrier/state maps
    ├── main.py            # CLI entry point
    └── version.py         # Single source of truth for version
```

---

## Running Tests

```powershell
# Feature tests
python -m pytest veilux_ng/tests/ -v

# All tests (unit + integration)
python -m pytest veilux_ng/tests/ tests/ -v
```

---

## Documentation

- [API Reference](docs/API.md)
- [Legal & NDPA 2023 Compliance](docs/LEGAL.md)

---

## Legal

All features operate exclusively on **publicly available data** under NDPA 2023 Section 31.
No consent required. No personal data stored. See [LEGAL.md](docs/LEGAL.md).

---

*Powered by Lordradeez.exe*
