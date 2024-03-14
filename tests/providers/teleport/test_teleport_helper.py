import datetime
import json
import logging
import re
import shutil
from pathlib import Path
from unittest.mock import Mock, patch

import cryptography.x509
import pytest

import secrets_env.providers.teleport.helper as t
from secrets_env.exceptions import (
    AuthenticationError,
    SecretsEnvError,
    UnsupportedError,
)
from secrets_env.providers.teleport.config import TeleportUserConfig
from secrets_env.providers.teleport.helper import (
    TeleportAppConfig,
    TeleportConnectionParameter,
    call_app_config,
    call_version,
    get_connection_param,
    try_get_app_config,
)
from secrets_env.subprocess import Run

no_teleport_cli = shutil.which("tsh") is None


@pytest.fixture()
def dummy_param():
    return TeleportConnectionParameter(
        uri="https://example.com", ca=b"ca", cert=b"cert", key=b"key"
    )


class TestTeleportAppConfig:
    def test_1(self, tmp_path: Path):
        text = json.dumps(
            {
                "uri": "https://example.com",
                "ca": str(tmp_path / "ca.crt"),
                "cert": str(tmp_path / "cert.crt"),
                "key": str(tmp_path / "key.key"),
            }
        )
        assert TeleportAppConfig.model_validate_json(text) == TeleportAppConfig(
            uri="https://example.com",
            ca=tmp_path / "ca.crt",
            cert=tmp_path / "cert.crt",
            key=tmp_path / "key.key",
        )

    def test_2(self, tmp_path: Path):
        text = json.dumps(
            {
                "uri": "https://example.com",
                "ca": None,
                "cert": str(tmp_path / "cert.crt"),
                "key": str(tmp_path / "key.key"),
            }
        )
        assert TeleportAppConfig.model_validate_json(text) == TeleportAppConfig(
            uri="https://example.com",
            ca=None,
            cert=tmp_path / "cert.crt",
            key=tmp_path / "key.key",
        )


class TestGetConnectionParam:
    @pytest.fixture()
    def _patch_which(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr("shutil.which", lambda _: "/path/cmd")

    @pytest.fixture()
    def _patch_version(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(t, "call_version", lambda: True)

    @pytest.fixture()
    def _patch_call_app_login(self, monkeypatch: pytest.MonkeyPatch):
        def mock_call_app_login(params): ...

        monkeypatch.setattr(t, "call_app_login", mock_call_app_login)

    @pytest.mark.usefixtures(
        "_patch_which",
        "_patch_version",
        "_patch_call_app_login",
    )
    def test_success(
        self, monkeypatch: pytest.MonkeyPatch, dummy_param: TeleportConnectionParameter
    ):
        monkeypatch.setattr(t, "try_get_app_config", lambda _: None)
        monkeypatch.setattr(t, "call_app_config", lambda _: dummy_param)

        cfg = TeleportUserConfig(app="test")
        assert get_connection_param(cfg) == TeleportConnectionParameter(
            uri="https://example.com",
            ca=b"ca",
            cert=b"cert",
            key=b"key",
        )

    def test_missing_dependency(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr("shutil.which", lambda _: None)
        with pytest.raises(UnsupportedError):
            get_connection_param(TeleportUserConfig(app="test"))

    @pytest.mark.usefixtures("_patch_which")
    def test_internal_error(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(t, "call_version", lambda: False)
        with pytest.raises(SecretsEnvError):
            get_connection_param(TeleportUserConfig(app="test"))

    @pytest.mark.usefixtures("_patch_which", "_patch_version", "_patch_call_app_login")
    def test_no_config(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(t, "call_app_config", lambda _: None)
        with pytest.raises(AuthenticationError):
            get_connection_param(TeleportUserConfig(app="test"))
