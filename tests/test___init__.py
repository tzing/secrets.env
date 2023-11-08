import logging
from unittest.mock import Mock

import pytest

import secrets_env as t


class TestReadValues:
    @pytest.fixture()
    def _patch_load_config(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(
            "secrets_env.config0.load_config",
            lambda _: {
                "providers": Mock(),
                "requests": [Mock(), Mock()],
            },
        )

    @pytest.mark.usefixtures("_patch_load_config")
    def test_success(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ):
        monkeypatch.setattr(
            "secrets_env.collect.read_values", lambda _: {"foo": "mock", "bar": "test"}
        )

        with caplog.at_level(logging.INFO):
            assert t.read_values() == {"foo": "mock", "bar": "test"}

        assert "<mark>2</mark> secrets loaded" in caplog.text

    @pytest.mark.usefixtures("_patch_load_config")
    def test_success_partial(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ):
        monkeypatch.setattr(
            "secrets_env.collect.read_values", lambda _: {"foo": "mock"}
        )

        assert t.read_values() == {"foo": "mock"}
        assert "<error>1</error> / 2 secrets loaded" in caplog.text

    def test_no_config(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr("secrets_env.config0.load_config", lambda _: None)
        assert t.read_values() is None

    @pytest.mark.usefixtures("_patch_load_config")
    def test_strict(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ):
        monkeypatch.setattr(
            "secrets_env.collect.read_values", lambda _: {"foo": "mock"}
        )

        assert t.read_values(strict=True) is None
        assert "<error>1</error> / 2 secrets read." in caplog.text

    def test_no_value(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ):
        monkeypatch.setattr(
            "secrets_env.config0.load_config",
            lambda _: {
                "providers": Mock(),
                "requests": [],
            },
        )

        with caplog.at_level(logging.INFO):
            assert t.read_values() == {}

        assert not caplog.records
