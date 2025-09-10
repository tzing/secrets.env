import logging
from pathlib import Path

import pytest


@pytest.fixture
def _reset_logging():
    yield
    for logger in (logging.root, logging.getLogger("secrets_env")):
        logger.setLevel(logging.NOTSET)
        logger.propagate = True
        logger.handlers.clear()


@pytest.fixture(scope="session")
def repo_path() -> Path:
    this_dir = Path(__file__).resolve().parent
    return this_dir.parent
