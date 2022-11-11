import logging
from pathlib import Path

import httpx
import pytest
import respx


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


@pytest.fixture()
def unittest_respx() -> respx.Route:
    with respx.mock(base_url="https://example.com") as r:
        yield r
