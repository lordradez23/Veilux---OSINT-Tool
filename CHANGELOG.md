# Changelog

## [2.0.0] — 2024
### Added
- Complete rewrite as `veilux_ng` modular package
- 7 core OSINT features: URL Shortener, Phishing Detector, Social Discovery,
  Phone Analysis, Domain Analysis, Image Analysis, IP Intelligence
- NDPA 2023 compliance engine with per-feature legal basis registry
- Structured logging (console + daily rotating file)
- SQLite-backed URL shortener with anonymised click analytics
- CLI interface with interactive menu and argparse support
- Base feature class for consistent module interface
- Storage layer: Database manager + in-memory TTL cache
- API wrapper layer: OpenPhish, IPInfo, WHOIS
- Full test suite: unit, integration, performance
- Nigerian carrier/state prefix maps (NCC public data)
- Brand impersonation detection via Levenshtein distance
- Input sanitisation for all user-supplied data

### Removed
- Legacy `modules/` directory (18 old scripts)
- Legacy `Veilux.py` CLI entry point
- Legacy `gui.py` CustomTkinter interface

## [1.0.0] — 2023
- Initial release with basic OSINT modules
