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


class TestTryGetAppConfig:
    def test_success(self, monkeypatch: pytest.MonkeyPatch):
        conn_param = Mock(TeleportConnectionParameter)
        conn_param.is_cert_valid.return_value = True
        monkeypatch.setattr(
            "secrets_env.providers.teleport.config.call_app_config",
            lambda _: conn_param,
        )
        assert try_get_app_config("test") == conn_param

    def test_missing_dependency(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr("importlib.util.find_spec", lambda _: False)
        assert try_get_app_config("test") is None

    def test_no_config(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(
            "secrets_env.providers.teleport.config.call_app_config", lambda _: None
        )
        assert try_get_app_config("test") is None

    def test_not_valid(self, monkeypatch: pytest.MonkeyPatch):
        conn_param = Mock(TeleportConnectionParameter)
        conn_param.is_cert_valid.return_value = False
        monkeypatch.setattr(
            "secrets_env.providers.teleport.config.call_app_config",
            lambda _: conn_param,
        )
        assert try_get_app_config("test") is None


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


class TestTshAppConfigResponse:
    def test(self, tmp_path: Path):
        # test ca exists
        (tmp_path / "ca.crt").touch()
        (tmp_path / "cert.crt").touch()
        (tmp_path / "key.crt").touch()

        resp = TshAppConfigResponse.model_validate(
            {
                "uri": "https://example.com",
                "ca": str(tmp_path / "ca.crt"),
                "cert": str(tmp_path / "cert.crt"),
                "key": str(tmp_path / "key.key"),
            }
        )

        assert isinstance(resp, TshAppConfigResponse)
        assert resp.uri == "https://example.com"
        assert resp.ca == tmp_path / "ca.crt"
        assert resp.cert == tmp_path / "cert.crt"
        assert resp.key == tmp_path / "key.key"

        # test ca missing
        resp = TshAppConfigResponse.model_validate(
            {
                "uri": "https://example.com",
                "ca": str(tmp_path / "ca-2.crt"),
                "cert": str(tmp_path / "cert.crt"),
                "key": str(tmp_path / "key.key"),
            }
        )

        assert isinstance(resp, TshAppConfigResponse)
        assert resp.uri == "https://example.com"
        assert resp.ca is None
        assert resp.cert == tmp_path / "cert.crt"
        assert resp.key == tmp_path / "key.key"


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
