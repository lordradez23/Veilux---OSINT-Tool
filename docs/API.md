# VEILUX-NG API Reference
> Developer reference for the four intelligence modules.

---

## VeiluxEngine

### `investigate(identifier, feature=None) → InvestigationReport`

| Parameter | Type | Description |
|-----------|------|-------------|
| `identifier` | `str` | Phone number, IP address, URL, or username |
| `feature` | `str \| None` | Force a specific module (see keys below) |

**Feature keys:** `phone_analysis`, `ip_intelligence`, `social_discovery`, `url_intelligence`

**Auto-detection priority:**
1. Nigerian phone number → `phone_analysis`
2. IPv4 / IPv6 address → `ip_intelligence`
3. `http://` or `https://` URL → `url_intelligence`
4. Domain name → `url_intelligence`
5. Anything else → `social_discovery`

**Returns:** `InvestigationReport`
```python
@dataclass
class InvestigationReport:
    identifier: str
    detected_type: str
    timestamp: str              # ISO 8601 UTC
    results: dict[str, Any]    # keyed by module name
    compliance: dict[str, Any] # legal basis per module
    errors: dict[str, str]     # module-level errors
```

### `compliance_report() → list[ComplianceResult]`
Returns NDPA 2023 compliance status for all four modules.

---

## ModuleResult (shared base)

All four result dataclasses inherit from `ModuleResult`:

```python
@dataclass
class ModuleResult:
    module: str          # module name
    input_value: str     # original input
    timestamp: str       # ISO 8601 UTC
    warnings: list[str]
    data_sources: list[str]
```

---

## Phone Intelligence

### `PhoneAnalysis.analyze(phone_number) → PhoneReport`

**PhoneReport fields:**

| Field | Type | Description |
|-------|------|-------------|
| `normalized` | `str` | E.164 format (+2348031234567) |
| `is_valid` | `bool` | Whether the number is valid |
| `network_type` | `str` | Mobile or Landline |
| `carrier_name` | `str \| None` | MTN, Glo, Airtel, 9mobile, etc. |
| `country` | `str \| None` | Country name |
| `region` | `str \| None` | Nigerian state of initial registration |
| `region_note` | `str` | Accuracy caveat (portability disclaimer) |
| `prefix` | `str \| None` | 4-digit NCC prefix |
| `timezones` | `list \| None` | IANA timezone(s) |
| `scam_reports` | `int \| None` | Reports from shouldianswer.net |

---

## IP Intelligence

### `IPIntelligence.analyze(ip) → IPReport`

**IPReport fields:**

| Field | Type | Description |
|-------|------|-------------|
| `ip` | `str` | Input IP address |
| `is_valid` | `bool` | Whether the IP is valid |
| `is_private` | `bool` | Private/loopback/reserved range |
| `country` | `str \| None` | Country name |
| `region` | `str \| None` | Region/state |
| `city` | `str \| None` | City |
| `isp` | `str \| None` | Internet Service Provider |
| `asn` | `str \| None` | Autonomous System Number |
| `is_vpn` | `bool` | VPN detected |
| `is_proxy` | `bool` | Proxy detected |
| `is_tor` | `bool` | Tor exit node |
| `is_hosting` | `bool` | Datacenter/cloud infrastructure |
| `risk_score` | `int` | 0–100 composite risk score |
| `risk_flags` | `list[str]` | Risk indicators |
| `maps_url` | `str \| None` | Google Maps link |

**Provider priority:** IPinfo → Ipregistry → MaxMind → Spur → ip-api.com → ipwho.is

---

## Social Discovery

### `SocialDiscovery.discover(username) → SocialDiscoveryReport`

**SocialDiscoveryReport fields:**

| Field | Type | Description |
|-------|------|-------------|
| `username` | `str` | Input username |
| `found` | `list[ProfileResult]` | Confirmed public profiles |
| `not_found` | `list[ProfileResult]` | Platforms where profile was absent |
| `errors` | `list[ProfileResult]` | Platforms that timed out or blocked |
| `total_found` | `int` | Count of confirmed profiles |

**Platforms checked (15):** GitHub, Twitter/X, Instagram, TikTok, Reddit, YouTube, LinkedIn, Pinterest, Snapchat, Nairaland, Twitch, Medium, Dev.to, Keybase, HackerNews

---

## URL Intelligence

### `URLIntelligence.analyze(url) → URLIntelligenceReport`

**URLIntelligenceReport fields:**

| Field | Type | Description |
|-------|------|-------------|
| `url` | `str` | Input URL |
| `domain` | `str` | Extracted domain |
| `risk_score` | `int` | 0–100 heuristic score |
| `risk_level` | `str` | LOW / MEDIUM / HIGH / CRITICAL |
| `flags` | `list[str]` | Specific indicators triggered |
| `domain_age_days` | `int \| None` | Days since domain registration |
| `ssl_valid` | `bool \| None` | SSL certificate validity |
| `impersonated_brand` | `str \| None` | Brand being typosquatted |
| `threat_intel_hit` | `bool` | Found in OpenPhish feed |
| `verdict` | `str` | Human-readable summary |

**Note:** Risk scores are heuristic indicators. Only `threat_intel_hit=True` constitutes a confirmed threat feed match. All other findings require human review.
