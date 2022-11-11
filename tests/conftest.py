import logging
from pathlib import Path

import httpx
import pytest


@pytest.fixture()
def repo_path():
    this_dir = Path(__file__).resolve().parent
    return this_dir.parent


@pytest.fixture()
def _reset_logging():
    yield
    for logger in (logging.root, logging.getLogger("secrets_env")):
        logger.setLevel(logging.NOTSET)
        logger.propagate = True
        logger.handlers.clear()


@pytest.fixture()
def unittest_client() -> httpx.Client:
    return httpx.Client(base_url="https://example.com")
