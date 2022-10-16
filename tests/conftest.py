import logging
from pathlib import Path

import pytest


@pytest.fixture()
def repo_path():
    this_dir = Path(__file__).resolve().parent
    return this_dir.parent


@pytest.fixture()
def _reset_logging():
    yield
    for logger in (logging.root, logging.getLogger("secrets_env")):
        logger.setLevel(logging.WARNING)
        logger.propagate = True
        logger.disabled = False
        logger.handlers.clear()
        logger.filters.clear()
