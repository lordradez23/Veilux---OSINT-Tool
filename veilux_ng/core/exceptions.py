"""
VEILUX-NG Custom Exceptions
"""


class VeiluxError(Exception):
    """Base exception for all VEILUX-NG errors."""


class ComplianceError(VeiluxError):
    """Raised when a feature fails an NDPA 2023 compliance check."""


class ValidationError(VeiluxError, ValueError):
    """Raised when user input fails validation."""


class FeatureError(VeiluxError):
    """Raised when a feature module encounters a runtime error."""


class NetworkError(VeiluxError):
    """Raised when an external HTTP request fails after all retries."""


class StorageError(VeiluxError):
    """Raised when a database or cache operation fails."""
