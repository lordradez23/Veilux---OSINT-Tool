# VEILUX-NG API Reference

## VeiluxEngine

### `investigate(identifier, feature=None) → InvestigationReport`
Auto-detects identifier type and runs applicable modules.

| Parameter | Type | Description |
|-----------|------|-------------|
| identifier | str | Phone, IP, URL, domain, username, or image URL |
| feature | str \| None | Force a specific feature (see feature keys below) |

**Feature keys:** `url_shortener`, `phishing_detector`, `social_discovery`,
`phone_analysis`, `domain_analysis`, `image_analysis`, `ip_intelligence`

**Returns:** `InvestigationReport`
```python
@dataclass
class InvestigationReport:
    identifier: str
    detected_type: str
    results: dict[str, Any]     # keyed by feature name
    compliance: dict[str, Any]  # legal basis per feature
    errors: dict[str, str]      # any feature-level errors
```

---

### `shorten_url(long_url, campaign=None) → ShortenResult`
| Parameter | Type | Description |
|-----------|------|-------------|
| long_url | str | Full URL to shorten |
| campaign | str \| None | Optional campaign label |

**Returns:** `ShortenResult(short_code, long_url, short_url, campaign, created_at)`

---

### `compliance_report() → list[ComplianceResult]`
Returns NDPA 2023 compliance status for all 7 features.

---

## URLShortener

| Method | Parameters | Returns |
|--------|-----------|---------|
| `shorten(long_url, campaign)` | str, str\|None | ShortenResult |
| `record_click(short_code, ip, user_agent, city, country)` | str... | None |
| `get_analytics(short_code)` | str | ClickAnalytics \| None |
| `resolve(short_code)` | str | str \| None |

---

## PhishingDetector

| Method | Parameters | Returns |
|--------|-----------|---------|
| `analyze(url)` | str | PhishingReport |

**PhishingReport fields:** `url`, `domain`, `risk_score` (0–100), `risk_level`
(LOW/MEDIUM/HIGH/CRITICAL), `flags`, `domain_age_days`, `ssl_valid`,
`ssl_issuer`, `impersonated_brand`, `threat_intel_hit`, `verdict`

---

## SocialDiscovery

| Method | Parameters | Returns |
|--------|-----------|---------|
| `discover(username)` | str | SocialDiscoveryReport |

**SocialDiscoveryReport fields:** `username`, `found` (list), `not_found` (list),
`errors` (list), `total_found` (int)

---

## PhoneAnalysis

| Method | Parameters | Returns |
|--------|-----------|---------|
| `analyze(phone_number)` | str | PhoneReport |

**PhoneReport fields:** `raw_input`, `normalized`, `is_valid`, `carrier_name`,
`country`, `region`, `prefix`, `timezones`, `scam_reports`, `scam_score`

---

## DomainAnalysis

| Method | Parameters | Returns |
|--------|-----------|---------|
| `analyze(domain)` | str | DomainReport |

**DomainReport fields:** `domain`, `registrar`, `registered_on`, `expires_on`,
`age_days`, `name_servers`, `dns_records`, `ssl` (SSLInfo), `hosting_ip`,
`hosting_org`

---

## ImageAnalysis

| Method | Parameters | Returns |
|--------|-----------|---------|
| `analyze(image_url)` | str | ImageReport |

**ImageReport fields:** `format`, `width`, `height`, `file_size_kb`,
`camera_make`, `camera_model`, `date_taken`, `gps` (GPSCoordinates\|None),
`exif_raw`, `reverse_search_links`, `tampering_indicators`

---

## IPIntelligence

| Method | Parameters | Returns |
|--------|-----------|---------|
| `analyze(ip)` | str | IPReport |

**IPReport fields:** `ip`, `is_valid`, `is_private`, `country`, `region`,
`city`, `latitude`, `longitude`, `timezone`, `isp`, `org`, `asn`,
`is_proxy`, `is_hosting`, `risk_score`, `risk_flags`, `maps_url`
