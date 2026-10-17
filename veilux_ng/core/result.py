"""
VEILUX-NG Shared Result Base
All four module result dataclasses inherit from ModuleResult,
giving the engine and formatter a predictable shared surface.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class ModuleResult:
    """Minimal shared base for all four module result dataclasses."""
    module: str
    input_value: str
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    warnings: list[str] = field(default_factory=list)
    data_sources: list[str] = field(default_factory=list)
