from pathlib import Path

import pytest


@pytest.fixture()
def repo_path():
    this_dir = Path(__file__).resolve().parent
    return this_dir.parent
