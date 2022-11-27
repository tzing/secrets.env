import logging
from pathlib import Path
from typing import Iterable

import httpx
import pytest
import respx


@pytest.fixture()
def _reset_logging():
    yield
    for logger in (logging.root, logging.getLogger("secrets_env")):
        logger.setLevel(logging.NOTSET)
        logger.propagate = True
        logger.handlers.clear()


@pytest.fixture()
def _disable_ensure_path_exist_check(monkeypatch):
    def ensure_path(_, path):
        return Path(path), True

    monkeypatch.setattr("secrets_env.utils.ensure_path", ensure_path)
    monkeypatch.setattr("secrets_env.config.parser.ensure_path", ensure_path)


@pytest.fixture(scope="session")
def repo_path() -> Path:
    this_dir = Path(__file__).resolve().parent
    return this_dir.parent


@pytest.fixture(scope="session")
def fixture_dir(repo_path: Path) -> Path:
    return repo_path / "tests" / "fixtures"


@pytest.fixture()
def unittest_client() -> httpx.Client:
    return httpx.Client(base_url="https://example.com")


@pytest.fixture()
def unittest_respx() -> Iterable[respx.MockRouter]:
    with respx.mock(base_url="https://example.com") as r:
        yield r
