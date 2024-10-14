import datetime
import io
import json
import logging
import re
import shutil
import subprocess
import textwrap
from pathlib import Path
from unittest.mock import Mock

import cryptography.x509
import pexpect
import pytest
from pydantic import SecretBytes

from secrets_env.exceptions import AuthenticationError, UnsupportedError
from secrets_env.providers.teleport.config import (
    TeleportConnectionParameter,
    TeleportUserConfig,
    TshAppConfigResponse,
    call_app_config,
    call_app_login,
    call_version,
    ensure_dependencies,
    try_get_app_config,
)

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

    @pytest.fixture
    def _ensure_dependencies(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(
            "secrets_env.providers.teleport.config.ensure_dependencies", lambda: None
        )

    @pytest.mark.usefixtures("_ensure_dependencies")
    def test_connection_param_1(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(
            "secrets_env.providers.teleport.config.call_version",
            lambda: True,
        )
        monkeypatch.setattr(
            "secrets_env.providers.teleport.config.try_get_app_config",
            lambda _: Mock(TeleportConnectionParameter),
        )

        cfg = TeleportUserConfig(app="test")
        assert isinstance(cfg.connection_param, TeleportConnectionParameter)

    @pytest.mark.usefixtures("_ensure_dependencies")
    def test_connection_param_2(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(
            "secrets_env.providers.teleport.config.call_version",
            lambda: True,
        )
        monkeypatch.setattr(
            "secrets_env.providers.teleport.config.try_get_app_config",
            lambda _: None,
        )
        monkeypatch.setattr(
            "secrets_env.providers.teleport.config.call_app_login",
            lambda _: None,
        )
        monkeypatch.setattr(
            "secrets_env.providers.teleport.config.call_app_config",
            lambda _: Mock(TeleportConnectionParameter),
        )

        cfg = TeleportUserConfig(app="test")
        assert isinstance(cfg.connection_param, TeleportConnectionParameter)

    @pytest.mark.usefixtures("_ensure_dependencies")
    def test_connection_param_version_error(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(
            "secrets_env.providers.teleport.config.call_version",
            lambda: False,
        )
        cfg = TeleportUserConfig(app="test")
        with pytest.raises(RuntimeError):
            cfg.connection_param  # noqa: B018

    @pytest.mark.usefixtures("_ensure_dependencies")
    def test_connection_param_no_config(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(
            "secrets_env.providers.teleport.config.call_version",
            lambda: True,
        )
        monkeypatch.setattr(
            "secrets_env.providers.teleport.config.try_get_app_config",
            lambda _: None,
        )
        monkeypatch.setattr(
            "secrets_env.providers.teleport.config.call_app_login",
            lambda _: None,
        )
        monkeypatch.setattr(
            "secrets_env.providers.teleport.config.call_app_config",
            lambda _: None,
        )

        cfg = TeleportUserConfig(app="test")
        with pytest.raises(AuthenticationError):
            cfg.connection_param  # noqa: B018


class TestEnsureDependencies:

    def test_pass(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr("shutil.which", lambda _: "/mock/tsh")
        assert ensure_dependencies() is None

    def test_missing_tsh(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr("shutil.which", lambda _: None)
        with pytest.raises(UnsupportedError):
            ensure_dependencies()

    @pytest.mark.filterwarnings(
        "ignore::UserWarning:secrets_env.providers.teleport.config"
    )
    def test_missing_dependency(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr("shutil.which", lambda _: "/mock/tsh")
        monkeypatch.setattr("importlib.util.find_spec", lambda _: None)
        with pytest.raises(UnsupportedError):
            ensure_dependencies()


class TestTeleportConnectionParameter:
    def test_model_validate_with_ca(self, tmp_path: Path):
        (tmp_path / "ca.crt").write_bytes(
            b"subject=/C=XX/L=Default City/O=Test\n-----MOCK CERTIFICATE-----"
        )
        (tmp_path / "cert.crt").write_bytes(b"-----MOCK CERTIFICATE-----")
        (tmp_path / "key.key").write_bytes(b"-----MOCK PRIVATE KEY-----")

        param = TeleportConnectionParameter.model_validate(
            TshAppConfigResponse(
                uri="https://example.com",
                ca=tmp_path / "ca.crt",
                cert=tmp_path / "cert.crt",
                key=tmp_path / "key.key",
            )
        )

        assert param.path_ca.read_bytes() == (
            b"subject=/C=XX/L=Default City/O=Test\n" b"-----MOCK CERTIFICATE-----"
        )
        assert param.path_cert.read_bytes() == b"-----MOCK CERTIFICATE-----"
        assert param.path_key.read_bytes() == b"-----MOCK PRIVATE KEY-----"
        assert param.path_cert_and_key.read_bytes() == (
            b"-----MOCK CERTIFICATE-----\n" b"-----MOCK PRIVATE KEY-----"
        )

    def test_model_validate_without_ca(self, tmp_path: Path):
        (tmp_path / "cert.crt").write_bytes(b"-----MOCK CERTIFICATE-----")
        (tmp_path / "key.key").write_bytes(b"-----MOCK PRIVATE KEY-----")

        param = TeleportConnectionParameter.model_validate(
            TshAppConfigResponse(
                uri="https://example.com",
                ca=tmp_path / "not-exist.crt",
                cert=tmp_path / "cert.crt",
                key=tmp_path / "key.key",
            )
        )

        assert param.path_ca is None

    def test_model_validate(self):
        param = TeleportConnectionParameter.model_validate(
            {
                "uri": "https://example.com",
                "ca": None,
                "cert": b"cert data",
                "key": b"key data",
            }
        )

        assert param.cert == SecretBytes(b"cert data")
        assert param.key == SecretBytes(b"key data")

    def test_cert_valid(
        self, monkeypatch: pytest.MonkeyPatch, conn_param: TeleportConnectionParameter
    ):
        later = datetime.datetime.now().astimezone() + datetime.timedelta(days=30)

        cert = Mock(cryptography.x509.Certificate)
        cert.not_valid_after_utc = later

        monkeypatch.setattr(
            "cryptography.x509.load_pem_x509_certificate", lambda _: cert
        )

        assert conn_param.is_cert_valid() is True

    def test_cert_expired(self):
        FAKE_CERT = textwrap.dedent(
            """
            -----BEGIN CERTIFICATE-----
            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
            -----END CERTIFICATE-----
            """
        ).encode()

        param = TeleportConnectionParameter(
            uri="https://example.com",
            ca=None,
            cert=FAKE_CERT,
            key=b"-----MOCK PRIVATE KEY-----",
        )

        assert param.is_cert_valid() is False


class TestTryGetAppConfig:
    def test_success(self, monkeypatch: pytest.MonkeyPatch):
        conn_param = Mock(TeleportConnectionParameter)
        conn_param.is_cert_valid.return_value = True
        monkeypatch.setattr(
            "secrets_env.providers.teleport.config.call_app_config",
            lambda n, f: conn_param,
        )
        assert try_get_app_config("test") == conn_param

    def test_no_config(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(
            "secrets_env.providers.teleport.config.call_app_config",
            lambda n, f: None,
        )
        assert try_get_app_config("test") is None

    def test_not_valid(self, monkeypatch: pytest.MonkeyPatch):
        conn_param = Mock(TeleportConnectionParameter)
        conn_param.is_cert_valid.return_value = False
        monkeypatch.setattr(
            "secrets_env.providers.teleport.config.call_app_config",
            lambda n, f: conn_param,
        )
        assert try_get_app_config("test") is None


class TestCallVersion:
    @pytest.mark.skipif(tsh_not_installed, reason="Teleport CLI not installed")
    def test_success(self, caplog: pytest.LogCaptureFixture):
        with caplog.at_level(logging.DEBUG):
            assert call_version() is True
        assert re.search(r"<\[stdout\] Teleport v\d+\.\d+\.\d+", caplog.text)

    def test_fail(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(
            "subprocess.run",
            Mock(side_effect=subprocess.CalledProcessError(1, "mock")),
        )
        assert call_version() is False


class TestTshAppConfigResponse:
    def test_1(self, tmp_path: Path):
        (tmp_path / "ca.crt").touch()
        (tmp_path / "cert.crt").touch()
        (tmp_path / "key.key").touch()

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

    def test_2(self, tmp_path: Path):
        (tmp_path / "cert.crt").touch()
        (tmp_path / "key.key").touch()

        resp = TshAppConfigResponse.model_validate(
            {
                "uri": "https://example.com",
                "ca": str(tmp_path / "not-exist.crt"),
                "cert": str(tmp_path / "cert.crt"),
                "key": str(tmp_path / "key.key"),
            }
        )

        assert isinstance(resp, TshAppConfigResponse)
        assert resp.ca is None

    def test_3(self, tmp_path: Path):
        (tmp_path / "cert.crt").touch()
        (tmp_path / "key.key").touch()

        resp = TshAppConfigResponse.model_validate(
            {
                "uri": "https://example.com",
                "ca": None,
                "cert": str(tmp_path / "cert.crt"),
                "key": str(tmp_path / "key.key"),
            }
        )

        assert isinstance(resp, TshAppConfigResponse)
        assert resp.ca is None


class TestCallAppConfig:
    def test_success(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        conn_param: TeleportConnectionParameter,
    ):
        def mock_check_output(cmd, **kwargs):
            (tmp_path / "ca.crt").write_bytes(
                b"subject=/C=XX/L=Default City/O=Test\n-----MOCK CERTIFICATE-----"
            )
            (tmp_path / "cert.crt").write_bytes(b"-----MOCK CERTIFICATE-----")
            (tmp_path / "key.key").write_bytes(b"-----MOCK PRIVATE KEY-----")

            return json.dumps(
                {
                    "uri": "https://example.com",
                    "ca": str(tmp_path / "ca.crt"),
                    "cert": str(tmp_path / "cert.crt"),
                    "key": str(tmp_path / "key.key"),
                }
            )

        monkeypatch.setattr(
            "secrets_env.providers.teleport.config.check_output", mock_check_output
        )

        assert call_app_config("test") == conn_param

    def test_fail(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(
            "subprocess.run",
            Mock(side_effect=subprocess.CalledProcessError(1, "mock")),
        )
        assert call_app_config("test") is None


class TestCallAppLogin:
    def test_success(
        self,
        caplog: pytest.LogCaptureFixture,
        monkeypatch: pytest.MonkeyPatch,
    ):
        def mock_spawn(command, args, **kwargs):
            assert command == "tsh"
            assert args == [
                "app",
                "login",
                "--proxy=proxy.example.com",
                "--cluster=stg.example.com",
                "--user=user",
                "test",
            ]

            proc = Mock(pexpect.spawn)
            proc.expect = Mock(side_effect=[1, 3])

            pattern = re.compile(r"http://127\.0\.0\.1:\d+/[0-9a-f-]+")
            proc.match = pattern.match("http://127.0.0.1:12345/0000-0000-0000-0000")

            proc.close = Mock()
            proc.exitstatus = 0

            return proc

        monkeypatch.setattr("pexpect.spawn", mock_spawn)
        monkeypatch.setattr(
            "io.StringIO",
            Mock(
                side_effect=[
                    io.StringIO("If browser..."),
                    io.StringIO("mock stderr"),
                ]
            ),
        )

        config = TeleportUserConfig(
            proxy="proxy.example.com",
            cluster="stg.example.com",
            user="user",
            app="test",
        )
        with caplog.at_level("DEBUG"):
            call_app_login(config)

        assert "Waiting for response from Teleport..." in caplog.text
        assert "Successfully logged into teleport app: test" in caplog.text
        assert "<[stdout] If browser..." in caplog.text
        assert "<[stderr] mock stderr" in caplog.text

    def test_app_not_found(self, monkeypatch: pytest.MonkeyPatch):
        def mock_spawn(command, args, **kwargs):
            proc = Mock(pexpect.spawn)
            proc.expect = Mock(return_value=2)
            proc.close = Mock()
            proc.exitstatus = 1
            return proc

        monkeypatch.setattr("pexpect.spawn", mock_spawn)

        with pytest.raises(AuthenticationError, match="Teleport app 'test' not found"):
            call_app_login(TeleportUserConfig(app="test"))

    def test_other_error(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ):
        def mock_spawn(command, args, **kwargs):
            proc = Mock(pexpect.spawn)
            proc.expect = Mock(return_value=3)
            proc.close = Mock()
            proc.exitstatus = 1
            return proc

        monkeypatch.setattr("pexpect.spawn", mock_spawn)
        monkeypatch.setattr(
            "io.StringIO", Mock(return_value=io.StringIO("mock stderr"))
        )

        with pytest.raises(AuthenticationError, match="Teleport error"):
            call_app_login(TeleportUserConfig(app="test"))

        assert "<[stdout] mock stderr" in caplog.text
        assert "<[stderr] mock stderr" in caplog.text
