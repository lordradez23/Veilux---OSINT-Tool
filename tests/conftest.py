"""
VEILUX-NG Pytest Configuration & Shared Fixtures
"""

import sys
from pathlib import Path
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


@pytest.fixture
def sample_phone():
    return "08031234567"

@pytest.fixture
def sample_username():
    return "torvalds"

@pytest.fixture
def sample_domain():
    return "example.com"

@pytest.fixture
def sample_ip():
    return "8.8.8.8"

@pytest.fixture
def sample_url():
    return "https://www.example.com/path?q=1"

@pytest.fixture
def phishing_url():
    return "http://paypa1.com/login"

@pytest.fixture
def sample_image_url():
    return "https://upload.wikimedia.org/wikipedia/commons/thumb/4/47/PNG_transparency_demonstration_1.png/280px-PNG_transparency_demonstration_1.png"
