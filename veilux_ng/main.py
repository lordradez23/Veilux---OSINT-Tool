"""
VEILUX-NG: CLI Entry Point
Run: python -m veilux_ng.main
"""

from veilux_ng.cli.commands import run_cli


def main() -> None:
    run_cli()


if __name__ == "__main__":
    main()
