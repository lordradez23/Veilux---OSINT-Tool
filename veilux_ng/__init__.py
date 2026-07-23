"""
VEILUX-NG: Next Generation Nigerian OSINT Framework
Version: 2.0.0 | Author: Lordradeez.exe | NDPA 2023 Compliant
"""

from veilux_ng.core.engine import VeiluxEngine
from veilux_ng.core.compliance import ComplianceEngine
from veilux_ng.core.logger import get_logger
from veilux_ng.version import __version__, __author__, __license__

__all__ = ["VeiluxEngine", "ComplianceEngine", "get_logger", "__version__"]
