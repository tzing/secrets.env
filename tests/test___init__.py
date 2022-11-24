import logging
from pathlib import Path
from unittest.mock import Mock

import pytest

import secrets_env
from secrets_env.auth.null import NoAuth
from secrets_env.core import KVReader
from secrets_env.exception import AuthenticationError


@pytest.fixture()
def _patch_load_config(monkeypatch: pytest.MonkeyPatch):
    def mock_load_config(path):
        assert path is None or isinstance(path, Path)
        return {
            "client": {
                "url": "https://example.com/",
                "auth": NoAuth(),
                "ca_cert": Path("/data/ca.cert"),
            },
            "secrets": {
                "VAR1": ("secrets/sample1", "foo"),
                "VAR2": ("secrets/sample2", "bar"),
            },
        }

    monkeypatch.setattr("secrets_env.config.load_config", mock_load_config)


@pytest.mark.usefixtures("_patch_load_config")
def test_success(monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture):
    caplog.set_level(logging.INFO)
    monkeypatch.setattr(
        KVReader,
        "read_values",
        lambda _1, _2: {
            ("secrets/sample1", "foo"): "secret-1",
            ("secrets/sample2", "bar"): "secret-2",
        },
    )

    assert secrets_env.load_secrets(None) == {
        "VAR1": "secret-1",
        "VAR2": "secret-2",
    }
    assert "<mark>2</mark> secrets loaded" in caplog.text


@pytest.mark.usefixtures("_patch_load_config")
def test_partial_loaded(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
):
    monkeypatch.setattr(
        KVReader,
        "read_values",
        lambda _1, _2: {
            ("secrets/sample1", "foo"): "secret-1",
            ("secrets/sample2", "bar"): None,
        },
    )

    assert secrets_env.load_secrets(None) == {
        "VAR1": "secret-1",
        "VAR2": None,
    }
    assert "<error>1</error> / 2 secrets loaded" in caplog.text


def test_no_config(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr("secrets_env.config.load_config", lambda _: None)
    assert secrets_env.load_secrets(None) == {}


@pytest.mark.usefixtures("_patch_load_config")
def test_auth_error(monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture):
    monkeypatch.setattr(
        KVReader, "read_values", Mock(side_effect=AuthenticationError("test error"))
    )
    assert secrets_env.load_secrets(None) == {}
    assert "Authentication error: test error" in caplog.text
