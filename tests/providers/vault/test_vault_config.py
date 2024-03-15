from pathlib import Path

import pytest
from pydantic_core import Url

from secrets_env.providers.vault.auth.base import NullAuth
from secrets_env.providers.vault.config import (
    RawVaultUserConfig,
    TlsConfig,
    get_connection_info,
)


class TestRawVaultUserConfig:
    def test_success(self, tmp_path: Path):
        (tmp_path / "ca.cert").touch()
        (tmp_path / "client.pem").touch()
        (tmp_path / "client.key").touch()

        config = RawVaultUserConfig.model_validate(
            {
                "url": "https://example.com",
                "auth": {"method": "null"},
                "proxy": "http://proxy.example.com",
                "tls": {
                    "ca_cert": tmp_path / "ca.cert",
                    "client_cert": tmp_path / "client.pem",
                    "client_key": tmp_path / "client.key",
                },
            }
        )

        assert isinstance(config, RawVaultUserConfig)
        assert config.url == Url("https://example.com")
        assert config.auth == {"method": "null"}
        assert config.proxy == Url("http://proxy.example.com")
        assert config.tls == TlsConfig(
            ca_cert=tmp_path / "ca.cert",
            client_cert=tmp_path / "client.pem",
            client_key=tmp_path / "client.key",
        )

    def test_url(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("SECRETS_ENV_ADDR", "https://env.example.com")
        config = RawVaultUserConfig.model_validate({"auth": "null"})
        assert isinstance(config, RawVaultUserConfig)
        assert config.url == Url("https://env.example.com")

    def test_auth(self):
        # shortcut
        config = RawVaultUserConfig.model_validate(
            {"url": "https://example.com", "auth": "null"}
        )
        assert isinstance(config, RawVaultUserConfig)
        assert config.auth == {"method": "null"}

        # use default
        config = RawVaultUserConfig.model_validate({"url": "https://example.com"})
        assert isinstance(config, RawVaultUserConfig)
        assert config.auth == {"method": "token"}

        # missing method
        with pytest.raises(
            ValueError, match="Missing required config <mark>auth method</mark>"
        ):
            RawVaultUserConfig.model_validate(
                {
                    "url": "https://example.com",
                    "auth": {"foo": "bar"},
                }
            )

    def test_proxy(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("SECRETS_ENV_PROXY", "http://env.proxy.example.com")
        config = RawVaultUserConfig.model_validate(
            {"url": "https://example.com", "auth": "null"}
        )
        assert isinstance(config, RawVaultUserConfig)
        assert config.proxy == Url("http://env.proxy.example.com")


class TestTlsConfig:
    def test_use_env_var(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
        (tmp_path / "ca.cert").touch()
        (tmp_path / "client.pem").touch()
        (tmp_path / "client.key").touch()

        monkeypatch.setenv("SECRETS_ENV_CA_CERT", str(tmp_path / "ca.cert"))
        monkeypatch.setenv("SECRETS_ENV_CLIENT_CERT", str(tmp_path / "client.pem"))
        monkeypatch.setenv("SECRETS_ENV_CLIENT_KEY", str(tmp_path / "client.key"))

        assert TlsConfig.model_validate({}) == TlsConfig(
            ca_cert=tmp_path / "ca.cert",
            client_cert=tmp_path / "client.pem",
            client_key=tmp_path / "client.key",
        )

    def test_require_client_cert(self, tmp_path: Path):
        (tmp_path / "client.key").touch()

        with pytest.raises(
            ValueError, match="client_cert is required when client_key is provided"
        ):
            TlsConfig(client_key=tmp_path / "client.key")


class TestGetConnectionInfo:
    def test_success_1(self):
        parsed = get_connection_info(
            {
                "url": "https://example.com",
                "auth": "null",
            }
        )
        assert isinstance(parsed, dict)
        assert parsed["url"] == "https://example.com/"
        assert parsed["auth"] == NullAuth()

    def test_success_2(self, tmp_path: Path):
        (tmp_path / "ca.cert").touch()
        (tmp_path / "client.pem").touch()
        (tmp_path / "client.key").touch()

        parsed = get_connection_info(
            {
                "url": "https://example.com",
                "auth": "null",
                "tls": {
                    "ca_cert": tmp_path / "ca.cert",
                    "client_cert": tmp_path / "client.pem",
                    "client_key": tmp_path / "client.key",
                },
            }
        )
        assert isinstance(parsed, dict)
        assert parsed["ca_cert"] == tmp_path / "ca.cert"
        assert parsed["client_cert"] == (
            tmp_path / "client.pem",
            tmp_path / "client.key",
        )

    def test_success_3(self, tmp_path: Path):
        (tmp_path / "client.pem").touch()

        parsed = get_connection_info(
            {
                "url": "https://example.com",
                "auth": "null",
                "proxy": "http://proxy.example.com",
                "tls": {
                    "client_cert": tmp_path / "client.pem",
                },
            }
        )
        assert isinstance(parsed, dict)
        assert parsed["proxy"] == "http://proxy.example.com/"
        assert parsed["client_cert"] == tmp_path / "client.pem"

    def test_fail(self):
        assert get_connection_info({"auth": "null"}) is None
        assert (
            get_connection_info({"url": "https://example.com", "auth": "invalid"})
            is None
        )
