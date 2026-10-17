# Changelog

## [3.0.0] — 2025

### Added
- `ip_intelligence` wired into `VeiluxEngine` — auto-detection, dispatch, compliance
- `ModuleResult` shared base dataclass (`core/result.py`) — all four results carry `module`, `input_value`, `timestamp`, `warnings`, `data_sources`
- `InvestigationReport.timestamp` field (ISO 8601 UTC)
- IPv4 and IPv6 detection in `_detect_type()` — IPs no longer misclassified as domains
- `url_intelligence` module (renamed from `phishing_detector`) with `URLIntelligenceReport`
- Explicit feature validation — unsupported feature keys raise `ValueError` with a clear message
- Unified test suite under `tests/` (unit + integration)
- Save-report prompt in interactive CLI menu

### Changed
- Feature key `phishing_detector` → `url_intelligence` (breaking)
- CLI menu restructured: 4 modules + compliance report
- `config/settings.py` trimmed — removed unused keys
- `requirements.txt` / `setup.py` — removed `Pillow`, `dnspython`
- `veilux_ng/version.py` bumped to 3.0.0

### Removed
- `domain_analysis` module and all references (breaking)
- `image_analysis` module and all references (breaking)
- `url_shortener` module and all references (breaking)
- `engine.shorten_url()` method (breaking)
- `veilux_ng/tests/` directory — tests moved to `tests/unit/`
- `veilux_urls.db` committed database file
- `anonymize_ip()`, `parse_user_agent()` removed from helpers (url_shortener-only utilities); `parse_user_agent()` re-added as a general utility
- `validate_mac()` removed from validators (unused)
- `NIGERIAN_STATE_MAP` backwards-compat alias removed from constants
- Unused settings: `DATABASE_PATH`, `URL_SHORTENER_BASE`, `SHODAN_API_KEY`, `ABUSEIPDB_API_KEY`, `DOMSCAN_API_KEY`, `AHREFS_API_KEY`, `APININJAS_API_KEY`

---

## [2.0.0] — 2024
### Added
- Complete rewrite as `veilux_ng` modular package
- 7 features: URL Shortener, Phishing Detector, Social Discovery, Phone Analysis, Domain Analysis, Image Analysis, IP Intelligence
- NDPA 2023 compliance engine
- Structured logging, SQLite URL shortener, CLI, NCC prefix maps

### Removed
- Legacy `modules/` directory, `Veilux.py`, `gui.py`

## [1.0.0] — 2023
- Initial release
