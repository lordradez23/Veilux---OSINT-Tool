"""
VEILUX-NG Report Exporter
Writes InvestigationReport objects to disk as JSON or plain-text files.
"""

import json
import re
from pathlib import Path

from veilux_ng.core.logger import get_logger

logger = get_logger("reporter")

# Strip ANSI colour codes for plain-text output
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def strip_ansi(text: str) -> str:
    return _ANSI_RE.sub("", text)


def export_json(report, path: str) -> Path:
    """
    Write *report* as indented JSON to *path*.
    Returns the resolved Path that was written.
    """
    dest = Path(path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    with dest.open("w", encoding="utf-8") as fh:
        json.dump(report.to_dict(), fh, indent=2, ensure_ascii=False, default=str)
    logger.info("Report exported as JSON to %s", dest)
    return dest


def export_txt(report, formatted_str: str, path: str) -> Path:
    """
    Write *formatted_str* (the coloured terminal output) as plain text to *path*.
    ANSI escape sequences are stripped automatically.
    Returns the resolved Path that was written.
    """
    dest = Path(path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    with dest.open("w", encoding="utf-8") as fh:
        fh.write(strip_ansi(formatted_str))
        fh.write("\n")
    logger.info("Report exported as TXT to %s", dest)
    return dest
