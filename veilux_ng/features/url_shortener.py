"""
VEILUX-NG Feature 1: URL Shortener with Click Analytics
NDPA Basis: Aggregated analytics; IPs anonymised before storage (Section 24).
No personal data is retained.
"""

import hashlib
import sqlite3
import string
import random
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from veilux_ng.core.exceptions import ValidationError
from veilux_ng.core.logger import get_logger
from veilux_ng.utils.helpers import anonymize_ip, parse_user_agent
from veilux_ng.utils.validators import validate_url

logger = get_logger("url_shortener")

_DB_SCHEMA = """
CREATE TABLE IF NOT EXISTS urls (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    short_code  TEXT    UNIQUE NOT NULL,
    long_url    TEXT    NOT NULL,
    campaign    TEXT,
    created_at  TEXT    NOT NULL,
    total_clicks INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS clicks (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    short_code  TEXT NOT NULL,
    clicked_at  TEXT NOT NULL,
    ip_anon     TEXT,
    city        TEXT,
    country     TEXT,
    device_type TEXT,
    browser     TEXT,
    FOREIGN KEY (short_code) REFERENCES urls(short_code)
);
"""

_ALPHABET = string.ascii_letters + string.digits


@dataclass
class ShortenResult:
    short_code: str
    long_url: str
    short_url: str
    campaign: Optional[str]
    created_at: str


@dataclass
class ClickAnalytics:
    short_code: str
    long_url: str
    total_clicks: int
    created_at: str
    by_country: dict = field(default_factory=dict)
    by_device: dict = field(default_factory=dict)
    by_browser: dict = field(default_factory=dict)
    recent_clicks: list = field(default_factory=list)


class URLShortener:
    """
    Generates short URLs and tracks aggregated, anonymised click analytics.
    All IP addresses are anonymised before storage — NDPA Section 24 compliant.
    """

    BASE_URL = "http://veilux.local/"  # Replace with real domain in production

    def __init__(self, db_path: str = "veilux_urls.db") -> None:
        self.db_path = db_path
        self._init_db()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def shorten(self, long_url: str, campaign: Optional[str] = None) -> ShortenResult:
        """Shorten a URL and return the result."""
        if not validate_url(long_url):
            raise ValidationError(f"Invalid URL: {long_url}")

        short_code = self._generate_code(long_url)
        created_at = datetime.now(timezone.utc).isoformat()

        with self._connect() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO urls (short_code, long_url, campaign, created_at) "
                "VALUES (?, ?, ?, ?)",
                (short_code, long_url, campaign, created_at),
            )

        logger.info("Shortened URL [%s] → %s", long_url[:60], short_code)
        return ShortenResult(
            short_code=short_code,
            long_url=long_url,
            short_url=f"{self.BASE_URL}{short_code}",
            campaign=campaign,
            created_at=created_at,
        )

    def record_click(
        self,
        short_code: str,
        ip: str = "",
        user_agent: str = "",
        city: str = "",
        country: str = "",
    ) -> None:
        """Record a click event. IP is anonymised before storage."""
        ua_info = parse_user_agent(user_agent)
        ip_anon = anonymize_ip(ip) if ip else "unknown"
        clicked_at = datetime.now(timezone.utc).isoformat()

        with self._connect() as conn:
            conn.execute(
                "INSERT INTO clicks (short_code, clicked_at, ip_anon, city, country, device_type, browser) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (short_code, clicked_at, ip_anon, city, country,
                 ua_info["device_type"], ua_info["browser"]),
            )
            conn.execute(
                "UPDATE urls SET total_clicks = total_clicks + 1 WHERE short_code = ?",
                (short_code,),
            )
        logger.debug("Click recorded for [%s]", short_code)

    def get_analytics(self, short_code: str) -> Optional[ClickAnalytics]:
        """Return aggregated analytics for a short code."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT long_url, total_clicks, created_at FROM urls WHERE short_code = ?",
                (short_code,),
            ).fetchone()
            if not row:
                return None

            long_url, total_clicks, created_at = row

            by_country = self._aggregate(conn, short_code, "country")
            by_device = self._aggregate(conn, short_code, "device_type")
            by_browser = self._aggregate(conn, short_code, "browser")
            recent = conn.execute(
                "SELECT clicked_at, city, country, device_type, browser "
                "FROM clicks WHERE short_code = ? ORDER BY clicked_at DESC LIMIT 10",
                (short_code,),
            ).fetchall()

        return ClickAnalytics(
            short_code=short_code,
            long_url=long_url,
            total_clicks=total_clicks,
            created_at=created_at,
            by_country=by_country,
            by_device=by_device,
            by_browser=by_browser,
            recent_clicks=[dict(zip(("clicked_at", "city", "country", "device_type", "browser"), r)) for r in recent],
        )

    def resolve(self, short_code: str) -> Optional[str]:
        """Return the original long URL for a short code."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT long_url FROM urls WHERE short_code = ?", (short_code,)
            ).fetchone()
        return row[0] if row else None

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _generate_code(self, long_url: str, length: int = 8) -> str:
        """Generate a deterministic short code from the URL hash."""
        digest = hashlib.sha256(long_url.encode()).hexdigest()
        # Map hex chars to our alphabet for a URL-safe code
        code = "".join(_ALPHABET[int(c, 16) % len(_ALPHABET)] for c in digest[:length])
        return code

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript(_DB_SCHEMA)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _aggregate(conn: sqlite3.Connection, short_code: str, column: str) -> dict:
        rows = conn.execute(
            f"SELECT {column}, COUNT(*) as cnt FROM clicks "
            f"WHERE short_code = ? GROUP BY {column} ORDER BY cnt DESC",
            (short_code,),
        ).fetchall()
        return {r[0] or "Unknown": r[1] for r in rows}
