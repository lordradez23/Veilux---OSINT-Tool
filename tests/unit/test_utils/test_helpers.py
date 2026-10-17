"""
Unit tests — Helpers
"""

import pytest
from veilux_ng.utils.helpers import levenshtein, extract_domain, parse_user_agent


class TestLevenshtein:
    def test_identical(self):
        assert levenshtein("paypal", "paypal") == 0

    def test_one_edit(self):
        assert levenshtein("paypal", "paypa1") == 1

    def test_empty(self):
        assert levenshtein("", "abc") == 3


class TestExtractDomain:
    def test_strips_www(self):
        assert extract_domain("https://www.example.com/path") == "example.com"

    def test_no_www(self):
        assert extract_domain("https://example.com") == "example.com"


class TestParseUserAgent:
    def test_desktop_chrome(self):
        ua = "Mozilla/5.0 (Windows NT 10.0) AppleWebKit Chrome/124"
        result = parse_user_agent(ua)
        assert result["device_type"] == "Desktop"
        assert result["browser"] == "Chrome"

    def test_mobile(self):
        ua = "Mozilla/5.0 (Android 13; Mobile) Chrome/124"
        result = parse_user_agent(ua)
        assert result["device_type"] == "Mobile"
