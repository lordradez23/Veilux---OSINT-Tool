"""
VEILUX-NG CLI Formatters
Converts report dataclasses into readable terminal output.
"""

import sys
import colorama
colorama.init()

# Force UTF-8 output on Windows so box-drawing chars render correctly
if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from veilux_ng.core.engine import InvestigationReport

C = colorama.Fore
S = colorama.Style
B = colorama.Style.BRIGHT

_BANNER = r"""
{R}{B}██╗   ██╗███████╗██╗██╗     ██╗   ██╗██╗  ██╗{W}     /\___/\
{R}{B}██║   ██║██╔════╝██║██║     ██║   ██║╚██╗██╔╝{W}    (@ @)
{R}{B}██║   ██║█████╗  ██║██║     ██║   ██║ ╚███╔╝ {W}     )===( 
{R}{B}╚██╗ ██╔╝██╔══╝  ██║██║     ██║   ██║ ██╔██╗ {W}    /|   |\ 
{R}{B} ╚████╔╝ ███████╗██║███████╗╚██████╔╝██╔╝ ██╗{W}   / | | | \ 
{R}{B}  ╚═══╝  ╚══════╝╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝{W}  *  * *  *
{RESET}
{W}{B}VEILUX-NG v2.0.0 | By Lordradeez.exe | NDPA 2023 Compliant{RESET}
"""


def print_banner() -> None:
    print(_BANNER.format(
        R=C.RED, W=C.WHITE, B=B, RESET=S.RESET_ALL
    ))


def _divider(title: str = "") -> str:
    line = "-" * 55
    return f"\n{C.YELLOW}{line}{S.RESET_ALL}" + (f"\n  {C.WHITE}{title}{S.RESET_ALL}" if title else "")


def format_report(report: InvestigationReport) -> str:
    lines = [
        _divider(f"Investigation: {report.identifier[:50]}"),
        f"  Detected type : {report.detected_type}",
    ]

    for feature, result in report.results.items():
        lines.append(_divider(feature.replace("_", " ").title()))
        lines.extend(_format_result(feature, result))

    if report.errors:
        lines.append(_divider("Errors"))
        for feat, err in report.errors.items():
            lines.append(f"  {C.RED}[!] {feat}: {err}{S.RESET_ALL}")

    lines.append(f"\n{C.YELLOW}{'─' * 55}{S.RESET_ALL}\n")
    return "\n".join(lines)


def _format_result(feature: str, result) -> list[str]:
    if result is None:
        return [f"  {C.RED}No result returned.{S.RESET_ALL}"]

    lines = []
    G, W, R = C.GREEN, C.WHITE, S.RESET_ALL

    if feature == "phone_analysis":
        lines += [
            f"  Normalized  : {G}{result.normalized}{R}",
            f"  Valid       : {G}{result.is_valid}{R}",
            f"  Carrier     : {G}{result.carrier_name or 'Unknown'}{R}",
            f"  Country     : {G}{result.country or 'N/A'}{R}",
            f"  Region      : {G}{result.region or 'N/A'}{R}",
        ]
        if result.scam_reports is not None:
            lines.append(f"  Scam reports: {G}{result.scam_reports}{R}")

    elif feature == "domain_analysis":
        lines += [
            f"  Registrar   : {G}{result.registrar or 'N/A'}{R}",
            f"  Registered  : {G}{result.registered_on or 'N/A'}{R}",
            f"  Age         : {G}{result.age_days} days{R}",
            f"  Expires     : {G}{result.expires_on or 'N/A'}{R}",
            f"  Hosting IP  : {G}{result.hosting_ip or 'N/A'}{R}",
            f"  Hosting org : {G}{result.hosting_org or 'N/A'}{R}",
        ]
        if result.is_available is not None:
            avail_color = G if result.is_available else C.RED
            lines.append(f"  Available   : {avail_color}{'Yes' if result.is_available else 'No'}{R}")
        if result.valuation_usd is not None:
            lines.append(f"  Valuation   : {G}${result.valuation_usd:,.2f}{R}")
        if result.domain_rating is not None:
            lines.append(f"  Domain Rating: {G}{result.domain_rating}/100{R}" + (f" (Ahrefs rank #{result.ahrefs_rank})" if result.ahrefs_rank else ""))
        if result.ssl:
            lines.append(f"  SSL valid   : {G}{result.ssl.valid}{R}")
            lines.append(f"  SSL issuer  : {G}{result.ssl.issuer or 'N/A'}{R}")
            lines.append(f"  SSL expires : {G}{result.ssl.expires or 'N/A'} ({result.ssl.days_until_expiry} days){R}")
        for rtype, records in result.dns_records.items():
            lines.append(f"  DNS {rtype:<6}  : {G}{', '.join(records[:3])}{R}")
        if result.data_sources:
            lines.append(f"  Sources     : {G}{', '.join(result.data_sources)}{R}")

    elif feature == "phishing_detector":
        level_color = C.RED if result.risk_level in ("CRITICAL", "HIGH") else C.YELLOW
        lines += [
            f"  Domain      : {G}{result.domain}{R}",
            f"  Risk score  : {level_color}{result.risk_score}/100{R}",
            f"  Risk level  : {level_color}{result.risk_level}{R}",
            f"  Verdict     : {level_color}{result.verdict}{R}",
        ]
        if result.impersonated_brand:
            lines.append(f"  Brand hit   : {C.RED}{result.impersonated_brand}{R}")
        for flag in result.flags:
            lines.append(f"    {C.RED}[!]{R} {flag}")

    elif feature == "social_discovery":
        lines.append(f"  Found on {G}{result.total_found}{R} platform(s):")
        for p in result.found:
            lines.append(f"    {G}[+]{R} {p.platform:<14} {p.url}")
        if result.errors:
            lines.append(f"  Errors on {len(result.errors)} platform(s) (timeout/blocked)")

    elif feature == "image_analysis":
        dims = f"{result.width}x{result.height}px" if result.width and result.height else "N/A"
        lines += [
            f"  Format      : {G}{result.format or 'N/A'}{R}",
            f"  Dimensions  : {G}{dims}{R}",
            f"  File size   : {G}{result.file_size_kb or 'N/A'} KB{R}",
            f"  Camera      : {G}{result.camera_make or 'N/A'} {result.camera_model or ''}{R}",
            f"  Software    : {G}{result.software or 'N/A'}{R}",
            f"  Date taken  : {G}{result.date_taken or 'N/A'}{R}",
        ]
        if result.gps:
            lines.append(f"  GPS         : {G}{result.gps.latitude:.5f}, {result.gps.longitude:.5f}{R}")
            lines.append(f"  Maps        : {G}{result.gps.maps_url}{R}")
        for name, link in result.reverse_search_links.items():
            lines.append(f"  {G}{name}{R}: {G}{link}{R}")

    else:
        lines.append(f"  {str(result)}")

    return lines
