"""
VEILUX-NG Root Configuration
Loads from environment / .env file.
"""

import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(Path(__file__).parent.parent / ".env")

BASE_DIR = Path(__file__).resolve().parent.parent


class Settings:
    # Paths
    BASE_DIR: Path  = BASE_DIR
    LOGS_DIR: Path  = BASE_DIR / "logs"

    # IP Intelligence — optional premium providers
    IPINFO_TOKEN: str        = os.getenv("IPINFO_TOKEN", "")
    IPREGISTRY_API_KEY: str  = os.getenv("IPREGISTRY_API_KEY", "")
    MAXMIND_ACCOUNT_ID: str  = os.getenv("MAXMIND_ACCOUNT_ID", "")
    MAXMIND_LICENSE_KEY: str = os.getenv("MAXMIND_LICENSE_KEY", "")
    SPUR_API_TOKEN: str      = os.getenv("SPUR_API_TOKEN", "")

    # Phone Intelligence — optional
    VERIPHONE_API_KEY: str   = os.getenv("VERIPHONE_API_KEY", "")

    # Logging
    LOG_LEVEL: str       = os.getenv("LOG_LEVEL", "INFO")

    # Request settings
    REQUEST_TIMEOUT: int = int(os.getenv("REQUEST_TIMEOUT", "10"))
    MAX_RETRIES: int     = int(os.getenv("MAX_RETRIES", "2"))
    CACHE_TTL: int       = int(os.getenv("CACHE_TTL", "3600"))


class DevelopmentSettings(Settings):
    LOG_LEVEL: str = "DEBUG"


class ProductionSettings(Settings):
    LOG_LEVEL: str = "WARNING"


class TestingSettings(Settings):
    LOG_LEVEL: str = "ERROR"


settings = Settings()
