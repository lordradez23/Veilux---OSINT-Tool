"""
VEILUX-NG CLI Commands
Interactive menu + argparse-based dispatch for four OSINT modules.
Run: python -m veilux_ng.main [--feature FEATURE] [target]
"""

import argparse
import sys

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

import colorama
colorama.init()

from pathlib import Path
from veilux_ng import VeiluxEngine, __version__
from veilux_ng.cli.formatters import format_report, print_banner
from veilux_ng.core.reporter import export_json, export_txt

_FEATURES = [
    "phone_analysis",
    "ip_intelligence",
    "social_discovery",
    "url_intelligence",
]

_MENU = """
{Y}[1]{R} Phone Intelligence     {Y}[2]{R} IP Intelligence
{Y}[3]{R} Social Discovery       {Y}[4]{R} URL Intelligence
{Y}[5]{R} Compliance Report      {Y}[0]{R} Exit
"""

_FEATURE_MAP = {
    "1": "phone_analysis",
    "2": "ip_intelligence",
    "3": "social_discovery",
    "4": "url_intelligence",
}

_PROMPTS = {
    "phone_analysis":   "Enter Nigerian phone number (e.g. 08031234567): ",
    "ip_intelligence":  "Enter IP address (IPv4 or IPv6): ",
    "social_discovery": "Enter username (alphanumeric/underscore only): ",
    "url_intelligence": "Enter URL to analyse (e.g. https://...): ",
}

C = colorama.Fore
S = colorama.Style
R = S.RESET_ALL


def run_cli() -> None:
    parser = argparse.ArgumentParser(
        description="VEILUX-NG — OSINT Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("target", nargs="?", help="Target input (phone, IP, URL, username)")
    parser.add_argument("-f", "--feature", choices=_FEATURES, help="Run a specific module explicitly")
    parser.add_argument("--output", "-o", help="File path to write the report")
    parser.add_argument("--format", choices=["json", "txt"], default="json",
                        help="Output format when using --output (default: json)")
    parser.add_argument("--batch", "-b", help="Path to a text file with one target per line")
    args = parser.parse_args()

    engine = VeiluxEngine()

    # ---------------------------------------------------------------
    # Batch mode
    # ---------------------------------------------------------------
    if args.batch:
        batch_path = Path(args.batch)
        if not batch_path.is_file():
            print(f"{C.RED}Batch file not found: {args.batch}{R}")
            sys.exit(1)
        with batch_path.open("r", encoding="utf-8") as fh:
            lines = [l.strip() for l in fh if l.strip() and not l.strip().startswith("#")]
        summary = []
        for line in lines:
            report = engine.investigate(line)
            formatted = format_report(report)
            print(formatted)
            summary.append((line, report.detected_type,
                             ", ".join(report.results.keys()),
                             ", ".join(report.errors.keys())))
            if args.output:
                out_path = Path(args.output).with_name(f"{Path(line).stem}_report.txt")
                export_txt(report, formatted, str(out_path))
        print(f"\n{C.CYAN}Batch Summary:{R}")
        for tgt, typ, mods, errs in summary:
            print(f"  {tgt:<30} {typ:<10} {mods:<30} {errs}")
        return

    # ---------------------------------------------------------------
    # Non-interactive single target
    # ---------------------------------------------------------------
    if args.target:
        report = engine.investigate(args.target, feature=args.feature)
        formatted = format_report(report)
        print(formatted)
        if args.output:
            if args.format == "json":
                export_json(report, args.output)
            else:
                export_txt(report, formatted, args.output)
        return

    # ---------------------------------------------------------------
    # Interactive menu
    # ---------------------------------------------------------------
    print_banner()
    while True:
        print(_MENU.format(Y=C.YELLOW, R=R))
        try:
            choice = input(f"{C.GREEN}Select option: {R}").strip()
        except (KeyboardInterrupt, EOFError):
            sys.exit(0)

        if choice == "0":
            print(f"{C.RED}Goodbye.{R}")
            break

        if choice == "5":
            for c in engine.compliance_report():
                status = "[OK]" if c.is_compliant else "[X]"
                print(f"  {status} {c.feature:<22} {c.ndpa_section}")
            continue

        feature = _FEATURE_MAP.get(choice)
        if not feature:
            print(f"{C.RED}Invalid option.{R}")
            continue

        try:
            prompt = _PROMPTS.get(feature, "Enter target: ")
            target = input(f"{C.GREEN}{prompt}{R}").strip()
            if not target:
                continue
            report = engine.investigate(target, feature=feature)
            formatted = format_report(report)
            print(formatted)

            save = input(f"\n{C.YELLOW}Save report? (json/txt/n): {R}").strip().lower()
            if save in ("json", "txt"):
                out_path = f"report_{feature}.{save}"
                if save == "json":
                    export_json(report, out_path)
                else:
                    export_txt(report, formatted, out_path)
                print(f"{C.GREEN}Saved to {out_path}{R}")
        except Exception as exc:
            print(f"{C.RED}Error: {exc}{R}")

        input(f"\n{C.YELLOW}Press Enter to continue...{R}")
