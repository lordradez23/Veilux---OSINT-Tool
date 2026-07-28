"""
VEILUX-NG CLI Commands
Interactive menu + argparse-based dispatch.
Run: python -m veilux_ng.main [--feature FEATURE] [target]
"""

import argparse
import sys

# Force UTF-8 on Windows terminals (cp1252 breaks box-drawing and emoji chars)
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

import colorama
colorama.init()

from pathlib import Path
from veilux_ng import VeiluxEngine, __version__
from veilux_ng.cli.formatters import format_report, print_banner

_FEATURES = [
    "phone_analysis",
    "domain_analysis",
    "phishing_detector",
    "social_discovery",
    "image_analysis",
]

_MENU = """
{Y}[1]{R} Phone Analysis        {Y}[2]{R} Domain Analysis
{Y}[3]{R} Phishing Detector     {Y}[4]{R} Social Discovery
{Y}[5]{R} Image Analysis        {Y}[6]{R} Compliance Report
{Y}[0]{R} Exit
"""

_FEATURE_MAP = {
    "1": "phone_analysis",
    "2": "domain_analysis",
    "3": "phishing_detector",
    "4": "social_discovery",
    "5": "image_analysis",
}

_PROMPTS = {
    "phone_analysis":    "Enter Nigerian phone number (e.g. 08031234567): ",
    "domain_analysis":   "Enter domain (e.g. example.com): ",
    "phishing_detector": "Enter URL to check (e.g. https://...): ",
    "social_discovery":  "Enter username (alphanumeric/underscore only): ",
    "image_analysis":    "Enter image URL or local file path: ",
}

C = colorama.Fore
S = colorama.Style


def run_cli() -> None:
    # Initialize argument parser
    parser = argparse.ArgumentParser(description="Veilux-NG CLI")
    parser.add_argument("target", nargs="?", help="Target input (IP, domain, URL, etc.)")
    parser.add_argument("-f", "--feature", choices=_FEATURES, help="Feature to run explicitly")
    parser.add_argument("--output", "-o", help="File path to write the report (JSON or TXT).")
    parser.add_argument("--format", choices=["json", "txt"], default="json",
                        help="Output format when using --output (default json).")
    parser.add_argument("--batch", "-b", help="Path to a text file with one target per line for batch processing.")
    # If batch mode is used, ignore --target and --feature; they will be read per line.
    args = parser.parse_args()

    engine = VeiluxEngine()

    # ---------------------------------------------------------------
    # Batch mode (non-interactive only)
    # ---------------------------------------------------------------
    if args.batch:
        batch_path = Path(args.batch)
        if not batch_path.is_file():
            print(f"{C.RED}Batch file not found: {args.batch}{R}")
            sys.exit(1)
        with batch_path.open("r", encoding="utf-8") as fh:
            lines = [l.strip() for l in fh.readlines() if l.strip() and not l.strip().startswith("#")]
        summary = []
        for line in lines:
            report = engine.investigate(line)
            print(format_report(report))
            summary.append((line, report.detected_type, ", ".join(report.results.keys()), ", ".join(report.errors.keys())))
            if args.output:
                out_path = Path(args.output).with_name(f"{Path(line).stem}_report.txt")
                out_path.write_text(format_report(report), encoding="utf-8")
        # Print summary table
        print(f"\n{C.CYAN}Batch Summary:{R}")
        for tgt, typ, mods, errs in summary:
            print(f"  {tgt:<30} {typ:<10} {mods:<30} {errs}")
        return

    # ---------------------------------------------------------------
    # Non-interactive single target mode
    # ---------------------------------------------------------------
    if args.target:
        report = engine.investigate(args.target, feature=args.feature)
        formatted = format_report(report)
        print(formatted)
        if args.output:
            Path(args.output).write_text(formatted, encoding="utf-8")
        return

    # ---------------------------------------------------------------
    # Interactive menu (unchanged)
    # ---------------------------------------------------------------
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

        if choice == "6":
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
            target = input(f"{G}{prompt}{R}").strip()
            if not target:
                continue
            report = engine.investigate(target, feature=feature)
            print(format_report(report))
        except Exception as exc:
            print(f"{C.RED}Error: {exc}{R}")

        input(f"\n{C.YELLOW}Press Enter to continue...{R}")
