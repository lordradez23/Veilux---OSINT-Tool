# VEILUX-NG Legal & Compliance Guide
**Nigeria Data Protection Act (NDPA) 2023 — Compliance Framework**

---

## Overview

VEILUX-NG processes **only publicly available data**. No consent is required under
NDPA 2023 Section 31 (Public Data Exemption) for data that has been voluntarily
made public by the data subject or is mandated to be public by law.

---

## Module-by-Module Legal Basis

### 1. Phone Intelligence
- **Data processed:** Carrier prefix, state of initial registration (from NCC public tables)
- **Legal basis:** Section 31 — NCC prefix allocation is publicly published regulatory data
- **Consent required:** No — prefix data is not personal data
- **Limitation:** No real-time location tracking. Region reflects initial registration state; number portability means the subscriber may have moved.

### 2. IP Intelligence
- **Data processed:** City-level geolocation, ISP, ASN, proxy/VPN indicators
- **Legal basis:** Section 31 — GeoIP databases are publicly licensed; city-level geolocation is not personal data under NDPA
- **Consent required:** No
- **Limitation:** Geolocation accuracy varies by provider and IP type. No street-level data is used.

### 3. Social Discovery
- **Data processed:** Publicly visible profile URLs only
- **Legal basis:** Section 31 — public profiles are voluntarily disclosed by the subject
- **Consent required:** No — only public-facing profile existence is checked
- **Constraint:** Private/locked profiles are never accessed. A username match does not confirm that different accounts belong to the same person.

### 4. URL Intelligence
- **Data processed:** Public URL structure, WHOIS records, SSL certificate, OpenPhish feed
- **Legal basis:** Section 31 — WHOIS is a publicly mandated disclosure (ICANN policy); SSL certificates are public
- **Consent required:** No — URL analysis does not constitute personal data processing
- **Limitation:** Risk scores are heuristic indicators, not definitive proof of malice. Only OpenPhish feed matches constitute confirmed threat intelligence.

---

## NDPA 2023 Sections Referenced

| Section | Title | Application |
|---------|-------|-------------|
| Section 25 | Purpose Limitation | Data used only for stated OSINT purpose |
| Section 26 | Storage Limitation | Logs do not retain personal data |
| Section 27 | Integrity & Confidentiality | Secure logging; no sensitive data in logs |
| Section 31 | Public Data Exemption | Primary basis for all four modules |

---

## Ethical Guidelines

1. Use VEILUX-NG only for lawful investigative purposes
2. Do not use findings to harass, stalk, or harm individuals
3. Respect platform Terms of Service when conducting social discovery
4. Report confirmed phishing URLs to relevant authorities (EFCC, NCC)
5. Do not present heuristic risk scores as definitive proof of wrongdoing
6. Acknowledge limitations and uncertainty in all findings

---

## Disclaimer

VEILUX-NG is provided for educational and research purposes only.
The authors accept no liability for misuse. Users are solely responsible
for ensuring their use complies with applicable Nigerian law and NDPA 2023.
