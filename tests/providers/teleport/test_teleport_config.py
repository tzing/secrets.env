import datetime
import json
import logging
import re
import shutil
from pathlib import Path
from unittest.mock import Mock

import cryptography.x509
import pytest

from secrets_env.exceptions import AuthenticationError
from secrets_env.providers.teleport.config import (
    TeleportConnectionParameter,
    TeleportUserConfig,
    TshAppConfigResponse,
    call_app_config,
    call_app_login,
    call_version,
    try_get_app_config,
)
from secrets_env.subprocess import Run

tsh_not_installed = shutil.which("tsh") is None


class TestTeleportUserConfig:
    def test_model_validate(self):
        cfg = TeleportUserConfig.model_validate(
            {
                "app": "test",
                "proxy": "proxy",
                "cluster": "cluster",
            }
        )
        assert isinstance(cfg, TeleportUserConfig)
        assert cfg.app == "test"
        assert cfg.proxy == "proxy"
        assert cfg.cluster == "cluster"

    def test_model_validate_shortcut(self):
        cfg = TeleportUserConfig.model_validate("test")
        assert isinstance(cfg, TeleportUserConfig)
        assert cfg.app == "test"


class TestCallVersion:
    @pytest.mark.skipif(tsh_not_installed, reason="Teleport CLI not installed")
    def test_success(self, caplog: pytest.LogCaptureFixture):
        with caplog.at_level(logging.DEBUG):
            assert call_version() is True
        assert re.search(r"< Teleport v\d+\.\d+\.\d+", caplog.text)

    def test_fail(self, monkeypatch: pytest.MonkeyPatch):
        mock = Mock(spec=Run, return_code=1)
        mock.return_code = 1
        monkeypatch.setattr("secrets_env.providers.teleport.config.Run", lambda _: mock)
        assert call_version() is False


class TestCallAppConfig:
    def test_success(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        conn_param: TeleportConnectionParameter,
    ):
        (tmp_path / "cert.crt").write_bytes(b"-----MOCK CERTIFICATE-----")
        (tmp_path / "key.key").write_bytes(b"-----MOCK PRIVATE KEY-----")

        mock = Mock(spec=Run, return_code=0)
        mock.return_code = 0
        mock.stdout = json.dumps(
            {
                "uri": "https://example.com",
                "ca": str(tmp_path / "ca.crt"),
                "cert": str(tmp_path / "cert.crt"),
                "key": str(tmp_path / "key.key"),
            }
        )
        monkeypatch.setattr("secrets_env.providers.teleport.config.Run", lambda _: mock)

        assert call_app_config("test") == conn_param

    def test_fail(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(
            "secrets_env.providers.teleport.config.Run",
            lambda _: Mock(spec=Run, return_code=1),
        )
        assert call_app_config("test") is None


class TestCallAppLogin:
    def test_success(
        self,
        caplog: pytest.LogCaptureFixture,
        monkeypatch: pytest.MonkeyPatch,
    ):
        # setup mock
        def mock_run_command(cmd: list):
            assert cmd == [
                "tsh",
                "app",
                "login",
                "--proxy=proxy.example.com",
                "--cluster=stg.example.com",
                "--user=user",
                "test",
            ]

            run = Mock(Run, return_code=0)
            run.iter_any_output.return_value = [
                "If browser...",
                " http://127.0.0.1:12345/mock",
                "Logged into app test",
            ]
            return run

        monkeypatch.setattr(
            "secrets_env.providers.teleport.config.Run", mock_run_command
        )

        # run
        config = TeleportUserConfig(
            proxy="proxy.example.com",
            cluster="stg.example.com",
            user="user",
            app="test",
        )

        with caplog.at_level(logging.INFO):
            assert call_app_login(config) is None

        # test
        assert "Waiting for response from Teleport..." in caplog.text
        assert "Successfully logged into app test" in caplog.text

    def test_app_not_found(self, monkeypatch: pytest.MonkeyPatch):
        run = Mock(Run, return_code=1)
        run.iter_any_output.return_value = [
            'ERROR: app "test" not found',
        ]
        run.stderr = 'ERROR: app "test" not found'

        monkeypatch.setattr("secrets_env.providers.teleport.config.Run", lambda _: run)

        with pytest.raises(AuthenticationError, match="Teleport app 'test' not found"):
            assert call_app_login(TeleportUserConfig(app="test")) is None

    def test_other_error(self, monkeypatch: pytest.MonkeyPatch):
        run = Mock(Run, return_code=1)
        run.iter_any_output.return_value = [
            "ERROR: mocked",
        ]
        run.stderr = "ERROR: mocked"

        monkeypatch.setattr("secrets_env.providers.teleport.config.Run", lambda _: run)

        with pytest.raises(AuthenticationError, match="Teleport error: ERROR: mocked"):
            assert call_app_login(TeleportUserConfig(app="test")) is None
