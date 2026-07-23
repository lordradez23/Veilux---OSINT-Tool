"""
VEILUX-NG CLI Commands
Interactive menu + argparse-based dispatch.
Run: python -m veilux_ng.main [--feature FEATURE] [target]
"""

import argparse
import sys

import colorama
colorama.init()

from veilux_ng import VeiluxEngine, __version__
from veilux_ng.cli.formatters import format_report, print_banner

_FEATURES = [
    "phone_analysis",
    "ip_intelligence",
    "domain_analysis",
    "phishing_detector",
    "social_discovery",
    "url_shortener",
    "image_analysis",
]

_MENU = """
{Y}[1]{R} Phone Analysis        {Y}[2]{R} IP Intelligence
{Y}[3]{R} Domain Analysis       {Y}[4]{R} Phishing Detector
{Y}[5]{R} Social Discovery      {Y}[6]{R} URL Shortener
{Y}[7]{R} Image Analysis        {Y}[8]{R} Compliance Report
{Y}[0]{R} Exit
"""

_FEATURE_MAP = {
    "1": "phone_analysis",
    "2": "ip_intelligence",
    "3": "domain_analysis",
    "4": "phishing_detector",
    "5": "social_discovery",
    "6": "url_shortener",
    "7": "image_analysis",
}

C = colorama.Fore
S = colorama.Style


def run_cli() -> None:
    parser = argparse.ArgumentParser(
        prog="veilux-ng",
        description=f"VEILUX-NG v{__version__} — Nigerian OSINT Framework",
    )
    parser.add_argument("target", nargs="?", help="Target to investigate")
    parser.add_argument("--feature", "-f", choices=_FEATURES, help="Force a specific feature")
    parser.add_argument("--version", "-v", action="version", version=f"VEILUX-NG {__version__}")

    args = parser.parse_args()
    engine = VeiluxEngine()

    # Non-interactive mode
    if args.target:
        report = engine.investigate(args.target, feature=args.feature)
        print(format_report(report))
        return

    # Interactive menu
    print_banner()
    while True:
        Y, R, G = C.YELLOW, S.RESET_ALL, C.GREEN
        print(_MENU.format(Y=Y, R=R))
        try:
            choice = input(f"{G}Select option: {R}").strip()
        except (KeyboardInterrupt, EOFError):
            print(f"\n{C.RED}Goodbye.{R}")
            sys.exit(0)

        if choice == "0":
            print(f"{C.RED}Goodbye.{R}")
            break

        if choice == "8":
            for c in engine.compliance_report():
                status = "✅" if c.is_compliant else "❌"
                print(f"  {status} {c.feature:<22} {c.ndpa_section}")
            continue

        feature = _FEATURE_MAP.get(choice)
        if not feature:
            print(f"{C.RED}Invalid option.{R}")
            continue

        try:
            target = input(f"{G}Enter target: {R}").strip()
            if not target:
                continue
            report = engine.investigate(target, feature=feature)
            print(format_report(report))
        except Exception as exc:
            print(f"{C.RED}Error: {exc}{R}")

        input(f"\n{C.YELLOW}Press Enter to continue...{R}")
