"""
Unit tests — Validators
"""

import pytest
from veilux_ng.utils.validators import (
    validate_ip, validate_phone, validate_url, validate_domain,
    validate_username, validate_mac,
)


class TestValidateIP:
    def test_valid_ipv4(self):
        assert validate_ip("8.8.8.8") is True

    def test_valid_ipv6(self):
        assert validate_ip("2001:4860:4860::8888") is True

    def test_invalid_ip(self):
        assert validate_ip("999.999.999.999") is False

    def test_empty_string(self):
        assert validate_ip("") is False


class TestValidatePhone:
    def test_local_format(self):
        assert validate_phone("08031234567") is True

    def test_international_format(self):
        assert validate_phone("+2348031234567") is True

    def test_too_short(self):
        assert validate_phone("0803123") is False

    def test_letters(self):
        assert validate_phone("0803ABCDEFG") is False


class TestValidateURL:
    def test_valid_https(self):
        assert validate_url("https://example.com") is True

    def test_valid_http(self):
        assert validate_url("http://example.com/path") is True

    def test_no_scheme(self):
        assert validate_url("example.com") is False

    def test_empty(self):
        assert validate_url("") is False


class TestValidateDomain:
    def test_valid_domain(self):
        assert validate_domain("example.com") is True

    def test_valid_subdomain(self):
        assert validate_domain("sub.example.co.uk") is True

    def test_invalid_domain(self):
        assert validate_domain("not a domain") is False


class TestValidateUsername:
    def test_valid(self):
        assert validate_username("lordradeez") is True

    def test_with_underscore(self):
        assert validate_username("lord_radeez") is True

    def test_too_long(self):
        assert validate_username("a" * 51) is False

    def test_spaces(self):
        assert validate_username("user name") is False


class TestValidateMAC:
    def test_valid_colon(self):
        assert validate_mac("00:1A:2B:3C:4D:5E") is True

    def test_valid_dash(self):
        assert validate_mac("00-1A-2B-3C-4D-5E") is True

    def test_invalid(self):
        assert validate_mac("ZZZZZZ") is False
