"""
VEILUX-NG Logger
Structured logging — never stores sensitive/personal data.
"""

import logging
import os
from datetime import datetime


LOG_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "logs")
os.makedirs(LOG_DIR, exist_ok=True)

_LOG_FORMAT = "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s"
_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


def get_logger(name: str) -> logging.Logger:
    """Return a named logger writing to both console and a daily log file."""
    logger = logging.getLogger(f"veilux.{name}")
    if logger.handlers:
        return logger

    logger.setLevel(logging.DEBUG)

    # Console handler — INFO and above only
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    ch.setFormatter(logging.Formatter(_LOG_FORMAT, _DATE_FORMAT))

    # File handler — DEBUG and above, rotated daily
    log_file = os.path.join(LOG_DIR, f"veilux_{datetime.now().strftime('%Y%m%d')}.log")
    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter(_LOG_FORMAT, _DATE_FORMAT))

    logger.addHandler(ch)
    logger.addHandler(fh)
    return logger
