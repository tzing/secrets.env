import logging
from pathlib import Path
from typing import Iterable

import httpx
import pytest
import respx


@pytest.fixture()
def repo_path() -> Path:
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
def unittest_respx() -> Iterable[respx.MockRouter]:
    with respx.mock(base_url="https://example.com") as r:
        yield r


@pytest.fixture()
def fixture_dir(repo_path: Path) -> Path:
    return repo_path / "tests" / "fixtures"
