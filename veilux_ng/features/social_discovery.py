"""
VEILUX-NG Feature 3: Public Social Discovery
NDPA Basis: Only publicly visible profiles are indexed (Section 31).
Private/locked profiles are never accessed.
"""

import time
from dataclasses import dataclass, field
from typing import Optional

from veilux_ng.core.logger import get_logger
from veilux_ng.utils.helpers import safe_request
from veilux_ng.utils.validators import validate_username

logger = get_logger("social_discovery")

# Platform registry: name → (url_template, found_status_codes, not_found_status_codes)
_PLATFORMS: dict[str, dict] = {
    "GitHub":       {"url": "https://github.com/{}", "found": [200], "not_found": [404]},
    "Twitter/X":    {"url": "https://twitter.com/{}", "found": [200], "not_found": [404]},
    "Instagram":    {"url": "https://www.instagram.com/{}/", "found": [200], "not_found": [404]},
    "TikTok":       {"url": "https://www.tiktok.com/@{}", "found": [200], "not_found": [404]},
    "Reddit":       {"url": "https://www.reddit.com/user/{}", "found": [200], "not_found": [404]},
    "YouTube":      {"url": "https://www.youtube.com/@{}", "found": [200], "not_found": [404]},
    "LinkedIn":     {"url": "https://www.linkedin.com/in/{}", "found": [200], "not_found": [404]},
    "Pinterest":    {"url": "https://www.pinterest.com/{}/", "found": [200], "not_found": [404]},
    "Snapchat":     {"url": "https://www.snapchat.com/add/{}", "found": [200], "not_found": [404]},
    "Nairaland":    {"url": "https://www.nairaland.com/{}", "found": [200], "not_found": [404]},
    "Twitch":       {"url": "https://www.twitch.tv/{}", "found": [200], "not_found": [404]},
    "Medium":       {"url": "https://medium.com/@{}", "found": [200], "not_found": [404]},
    "Dev.to":       {"url": "https://dev.to/{}", "found": [200], "not_found": [404]},
    "Keybase":      {"url": "https://keybase.io/{}", "found": [200], "not_found": [404]},
    "HackerNews":   {"url": "https://news.ycombinator.com/user?id={}", "found": [200], "not_found": [404]},
}

_REQUEST_DELAY = 0.5  # seconds between requests — polite rate limiting


@dataclass
class ProfileResult:
    platform: str
    username: str
    url: str
    found: bool
    status_code: Optional[int] = None
    note: str = ""


@dataclass
class SocialDiscoveryReport:
    username: str
    found: list[ProfileResult] = field(default_factory=list)
    not_found: list[ProfileResult] = field(default_factory=list)
    errors: list[ProfileResult] = field(default_factory=list)

    @property
    def total_found(self) -> int:
        return len(self.found)


class SocialDiscovery:
    """
    Searches for a username across major public social platforms.
    Only checks publicly accessible profile URLs — no authentication used.
    Respects rate limits with inter-request delays.
    """

    def discover(self, username: str) -> SocialDiscoveryReport:
        if not validate_username(username):
            raise ValueError(f"Invalid username: '{username}'. Use alphanumeric/underscore only.")

        report = SocialDiscoveryReport(username=username)
        logger.info("Starting social discovery for username: %s", username)

        for platform, config in _PLATFORMS.items():
            url = config["url"].format(username)
            result = self._check_platform(platform, username, url, config)

            if result.found:
                report.found.append(result)
            elif result.status_code is None:
                report.errors.append(result)
            else:
                report.not_found.append(result)

            time.sleep(_REQUEST_DELAY)

        logger.info(
            "Social discovery complete for '%s': %d/%d platforms found.",
            username, report.total_found, len(_PLATFORMS),
        )
        return report

    def _check_platform(
        self, platform: str, username: str, url: str, config: dict
    ) -> ProfileResult:
        resp = safe_request(url, timeout=8)

        if resp is None:
            return ProfileResult(platform=platform, username=username, url=url,
                                 found=False, note="Request failed / timeout")

        if resp.status_code in config["found"]:
            # Extra guard: some platforms return 200 for non-existent users
            # with a "not found" body — check for common patterns
            if self._is_ghost_200(platform, resp.text):
                return ProfileResult(platform=platform, username=username, url=url,
                                     found=False, status_code=resp.status_code,
                                     note="Profile page returned 200 but appears empty")
            return ProfileResult(platform=platform, username=username, url=url,
                                 found=True, status_code=resp.status_code)

        if resp.status_code in config["not_found"]:
            return ProfileResult(platform=platform, username=username, url=url,
                                 found=False, status_code=resp.status_code)

        return ProfileResult(platform=platform, username=username, url=url,
                             found=False, status_code=resp.status_code,
                             note=f"Unexpected status {resp.status_code}")

    @staticmethod
    def _is_ghost_200(platform: str, body: str) -> bool:
        """Detect platforms that return HTTP 200 for missing users."""
        ghost_patterns = {
            "Reddit":    "Sorry, nobody on Reddit goes by that name.",
            "HackerNews": "No such user.",
            "Keybase":   "\"them\":[]",
        }
        pattern = ghost_patterns.get(platform)
        return bool(pattern and pattern in body)
