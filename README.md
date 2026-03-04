```diff
- ██╗   ██╗███████╗██╗██╗     ██╗   ██╗██╗  ██╗     /\___/\
- ██║   ██║██╔════╝██║██║     ██║   ██║╚██╗██╔╝    ( @ @ )
- ██║   ██║█████╗  ██║██║     ██║   ██║ ╚███╔╝      ) V ( 
- ╚██╗ ██╔╝██╔══╝  ██║██║     ██║   ██║ ██╔██╗     /|   |\
-  ╚████╔╝ ███████╗██║███████╗╚██████╔╝██╔╝ ██╗   / | | | \
-   ╚═══╝  ╚══════╝╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝  *  * *  *
```

# Veilux - Weaponized OSINT Framework
**By Lordradeez.exe**

> ["Weaponized OSINT Exploitation Framework - Unstoppable Digital Warfare"](file:///c:/Users/Lordradeez/Downloads/Veilux%20-%20Lordradeez.exe/Veilux/DOCUMENTARY.md)

Stealthy, modular OSINT suite for extensive reconnaissance including phone, username, metadata, domain/IP, geolocation, MAC address, URL unshortening, Google dorks, and more. Featuring an aggressive, high-contrast terminal UI and a modern GUI.

## Features

### Phase 1: Basic Recon
*   **Phone Lookup**: Retrieve carrier, country, and validity triangulation.
*   **Username Search**: Check availability across social platforms.
*   **Metadata Extraction**: Extract hidden EXIF data from images/files.
*   **Domain/IP Lookup**: Detailed Whois and IP information.
*   **Geolocation Trace**: Trace the physical location of an IP.
*   **Shodan Search**: Search the Shodan database for device info.

### Phase 2: Active Interrogation
*   **Email Breach Check**: Check if an email has appeared in data breaches.
*   **DNS Enumeration**: Fetch A, MX, NS, and TXT records.
*   **Port Scanner**: Multi-threaded service discovery on target servers.
*   **MAC Address Lookup**: Identify device manufacturers from MAC addresses.
*   **URL Unshortener**: Expand shortened links to see the real destination.
*   **Google Dorks Helper**: Generate advanced search queries for recon.

### Phase 3: Deep Reconnaissance
*   **Subdomain Scanner**: Find hidden subdomains in certificate logs (CRT.sh).
*   **CMS & Tech Detector**: Detect server headers and technology stack fingerprinting.
*   **Google History Scanner**: Analyze Google service traces for target emails.
*   **IP by Map**: Visual IP mapping and live tracking.

## User Interfaces

Veilux offers two primary ways to operate:

### 1. Terminal Framework (CLI)
Experience the full cinematic "Digital Blood" interface with matrix rain and aggressive boot sequences.
```powershell
python Veilux.py
```

### 2. Modern GUI (Graphical Interface)
A sleek, modern dashboard built with `customtkinter` for high-speed operations.
```powershell
python gui.py
```

---

## Setup

### Windows (PowerShell)
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### Requirements
- Python 3.8+
- Internet connection for API lookups
- `customtkinter`, `dnspython`, `mac-vendor-lookup`, `requests`, `fpdf`, etc.

## Documentation
For a deep dive into the architecture, manifesto, and operational protocols, see [DOCUMENTARY.md](file:///c:/Users/Lordradeez/Downloads/Veilux%20-%20Lordradeez.exe/Veilux/DOCUMENTARY.md).

---
*Powered by Lordradeez.exe*
