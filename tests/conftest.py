import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from nethawk.database.db import Database          # noqa: E402
from nethawk.ml.predictor import Predictor        # noqa: E402


@pytest.fixture
def db(tmp_path):
    return Database(tmp_path / "test.db")


@pytest.fixture(scope="session")
def predictor():
    """The shared model; trained automatically on first use if missing."""
    return Predictor()
