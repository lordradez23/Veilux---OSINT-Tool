"""
Unit tests — Social Discovery
Uses mocking to avoid live HTTP requests.
"""

import pytest
from unittest.mock import patch, MagicMock
from veilux_ng.features.social_discovery import SocialDiscovery, ProfileResult

_discovery = SocialDiscovery()


def _mock_response(status_code: int, text: str = "") -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    return resp


class TestSocialDiscovery:
    def test_invalid_username_raises(self):
        with pytest.raises(ValueError):
            _discovery.discover("user name with spaces!")

    def test_username_too_long_raises(self):
        with pytest.raises(ValueError):
            _discovery.discover("a" * 51)

    @patch("veilux_ng.features.social_discovery.safe_request")
    def test_found_profile_on_200(self, mock_req):
        mock_req.return_value = _mock_response(200, "<html>profile</html>")
        report = _discovery.discover("testuser")
        assert report.total_found > 0

    @patch("veilux_ng.features.social_discovery.safe_request")
    def test_not_found_on_404(self, mock_req):
        mock_req.return_value = _mock_response(404)
        report = _discovery.discover("testuser")
        assert report.total_found == 0
        assert len(report.not_found) > 0

    @patch("veilux_ng.features.social_discovery.safe_request")
    def test_request_failure_goes_to_errors(self, mock_req):
        mock_req.return_value = None
        report = _discovery.discover("testuser")
        assert len(report.errors) > 0

    @patch("veilux_ng.features.social_discovery.safe_request")
    def test_reddit_ghost_200_not_counted_as_found(self, mock_req):
        mock_req.return_value = _mock_response(
            200, "Sorry, nobody on Reddit goes by that name."
        )
        report = _discovery.discover("definitelynotarealuser99999")
        reddit_found = [r for r in report.found if r.platform == "Reddit"]
        assert len(reddit_found) == 0

    @patch("veilux_ng.features.social_discovery.safe_request")
    def test_report_username_preserved(self, mock_req):
        mock_req.return_value = _mock_response(404)
        report = _discovery.discover("lordradeez")
        assert report.username == "lordradeez"
