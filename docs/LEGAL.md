# VEILUX-NG Legal & Compliance Guide
**Nigeria Data Protection Act (NDPA) 2023 — Compliance Framework**

---

## Overview

VEILUX-NG processes **only publicly available data**. No consent is required under
NDPA 2023 Section 31 (Public Data Exemption) for data that has been voluntarily
made public by the data subject or is mandated to be public by law.

---

## Feature-by-Feature Legal Basis

### 1. URL Shortener & Click Analytics
- **Data processed:** Anonymised IP (last octet zeroed), city, country, device type, browser
- **Legal basis:** Section 24 (Data Minimisation) — IPs are anonymised before storage
- **Consent required:** No — operator-generated analytics on their own URLs
- **Retention:** Configurable; default indefinite for aggregate counts

### 2. Phishing Link Detector
- **Data processed:** Public URL structure, WHOIS records, SSL certificate, OpenPhish feed
- **Legal basis:** Section 31 — WHOIS is a publicly mandated disclosure (ICANN policy)
- **Consent required:** No — URL analysis is not personal data processing
- **Note:** No personal data is extracted or stored

### 3. Public Social Discovery
- **Data processed:** Publicly visible profile URLs only
- **Legal basis:** Section 31 — public profiles are voluntarily disclosed by the subject
- **Consent required:** No — only public-facing profile existence is checked
- **Constraint:** Private/locked profiles are never accessed

### 4. Nigerian Phone Analysis
- **Data processed:** Carrier prefix, state (from NCC public tables)
- **Legal basis:** Section 31 — NCC prefix allocation is publicly published regulatory data
- **Consent required:** No — prefix data is not personal data
- **Note:** No real-time location tracking is performed

### 5. Domain Analysis
- **Data processed:** WHOIS records, DNS records, SSL certificate, hosting IP
- **Legal basis:** Section 31 — ICANN/NCC mandate public WHOIS; DNS is public by design
- **Consent required:** No — domain registration data is publicly mandated
- **Note:** Registrant personal data (if present in WHOIS) is displayed but not stored

### 6. Image Analysis
- **Data processed:** EXIF metadata embedded in publicly accessible images
- **Legal basis:** Section 31 — metadata is published by the image owner when sharing publicly
- **Consent required:** No — metadata in public images is voluntarily disclosed
- **Constraint:** Only publicly accessible image URLs are analysed

### 7. IP Intelligence
- **Data processed:** City-level geolocation, ISP, ASN, proxy flag
- **Legal basis:** Section 31 — GeoIP databases are publicly licensed; city-level only
- **Consent required:** No — IP geolocation to city level is not personal data under NDPA
- **Note:** No street-level or precise location data is used

---

## NDPA 2023 Sections Referenced

| Section | Title | Application |
|---------|-------|-------------|
| Section 24 | Data Minimisation | IP anonymisation in URL analytics |
| Section 25 | Purpose Limitation | Data used only for stated OSINT purpose |
| Section 26 | Storage Limitation | Logs do not retain personal data |
| Section 27 | Integrity & Confidentiality | Secure logging; no sensitive data in logs |
| Section 31 | Public Data Exemption | Primary basis for all 7 features |

---

## Ethical Guidelines

1. Use VEILUX-NG only for lawful purposes
2. Do not use findings to harass, stalk, or harm individuals
3. Respect platform Terms of Service when conducting social discovery
4. Report confirmed phishing URLs to relevant authorities (EFCC, NCC)
5. Do not attempt to de-anonymise IP data

---

## Disclaimer

VEILUX-NG is provided for educational and research purposes only.
The authors accept no liability for misuse. Users are solely responsible
for ensuring their use complies with applicable Nigerian law and NDPA 2023.
