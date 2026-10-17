"""
VEILUX-NG CLI Formatters
Converts InvestigationReport dataclasses into readable terminal output.
"""

import sys
import colorama
colorama.init()

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
{W}{B}VEILUX-NG v3.0.0 | By Lordradeez.exe | NDPA 2023 Compliant{RESET}
"""


def print_banner() -> None:
    print(_BANNER.format(R=C.RED, W=C.WHITE, B=B, RESET=S.RESET_ALL))


def _divider(title: str = "") -> str:
    line = "-" * 55
    return f"\n{C.YELLOW}{line}{S.RESET_ALL}" + (
        f"\n  {C.WHITE}{title}{S.RESET_ALL}" if title else ""
    )


def format_report(report: InvestigationReport) -> str:
    lines = [
        _divider(f"Investigation: {report.identifier[:50]}"),
        f"  Detected type : {report.detected_type}",
        f"  Timestamp     : {report.timestamp}",
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
            f"  Network     : {G}{result.network_type}{R}",
            f"  Carrier     : {G}{result.carrier_name or 'Unknown'}{R}",
            f"  Country     : {G}{result.country or 'N/A'}{R}",
            f"  Region      : {G}{result.region or 'N/A'}{R}",
        ]
        if result.region_note:
            lines.append(f"  Note        : {C.YELLOW}{result.region_note}{R}")
        if result.scam_reports is not None:
            lines.append(f"  Scam reports: {G}{result.scam_reports}{R}")
        if result.veriphone_line_type is not None:
            lines.append(f"  Line type   : {G}{result.veriphone_line_type}{R}")
        if result.veriphone_carrier is not None:
            lines.append(f"  VP Carrier  : {G}{result.veriphone_carrier}{R}")
        if result.veriphone_valid is not None:
            vp_color = G if result.veriphone_valid else C.RED
            lines.append(f"  VP Valid    : {vp_color}{result.veriphone_valid}{R}")
        if result.warnings:
            for w in result.warnings:
                lines.append(f"  {C.YELLOW}[!] {w}{R}")

    elif feature == "ip_intelligence":
        priv = f" {C.YELLOW}(private/reserved){R}" if result.is_private else ""
        lines += [
            f"  IP          : {G}{result.ip}{R}{priv}",
            f"  Valid       : {G}{result.is_valid}{R}",
            f"  Country     : {G}{result.country or 'N/A'}{R}",
            f"  Region      : {G}{result.region or 'N/A'}{R}",
            f"  City        : {G}{result.city or 'N/A'}{R}",
            f"  ISP         : {G}{result.isp or 'N/A'}{R}",
            f"  ASN         : {G}{result.asn or 'N/A'}{R}",
            f"  Timezone    : {G}{result.timezone or 'N/A'}{R}",
        ]
        if result.maps_url:
            lines.append(f"  Maps        : {G}{result.maps_url}{R}")
        flags_str = ", ".join(filter(None, [
            "VPN" if result.is_vpn else "",
            "Proxy" if result.is_proxy else "",
            "Tor" if result.is_tor else "",
            "Hosting" if result.is_hosting else "",
            "Relay" if result.is_relay else "",
        ]))
        risk_color = C.RED if result.risk_score >= 45 else C.YELLOW if result.risk_score >= 20 else G
        lines.append(f"  Risk score  : {risk_color}{result.risk_score}/100{R}")
        if flags_str:
            lines.append(f"  Risk flags  : {C.RED}{flags_str}{R}")
        if result.data_sources:
            lines.append(f"  Sources     : {G}{', '.join(result.data_sources)}{R}")

    elif feature == "social_discovery":
        lines.append(f"  Found on {G}{result.total_found}{R} platform(s):")
        for p in result.found:
            lines.append(f"    {G}[+]{R} {p.platform:<14} {p.url}")
        if result.errors:
            lines.append(f"  {C.YELLOW}Unavailable: {len(result.errors)} platform(s) (timeout/blocked){R}")

    elif feature == "url_intelligence":
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
        if result.data_sources:
            lines.append(f"  Sources     : {G}{', '.join(result.data_sources)}{R}")

    else:
        lines.append(f"  {str(result)}")

    return lines
