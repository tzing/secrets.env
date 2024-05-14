import os
from pathlib import Path

import pytest
from pydantic_core import Url, ValidationError

from secrets_env.providers.vault.auth.base import NoAuth
from secrets_env.providers.vault.auth.token import TokenAuth
from secrets_env.providers.vault.config import (
    LazyProvidedMarker,
    TlsConfig,
    VaultUserConfig,
)


class TestVaultUserConfig:
    def test_success(self, tmp_path: Path):
        if "VAULT_ADDR" in os.environ:
            pytest.skip("VAULT_ADDR is set. Skipping test.")

        (tmp_path / "ca.cert").touch()
        (tmp_path / "client.pem").touch()
        (tmp_path / "client.key").touch()

        config = VaultUserConfig.model_validate(
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

        assert isinstance(config, VaultUserConfig)
        assert config.url == Url("https://example.com")
        assert config.auth == {"method": "null"}
        assert config.proxy == Url("http://proxy.example.com")
        assert config.tls == TlsConfig(
            ca_cert=tmp_path / "ca.cert",
            client_cert=tmp_path / "client.pem",
            client_key=tmp_path / "client.key",
        )

    def test_url__envvar(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("SECRETS_ENV_ADDR", "https://env.example.com")
        config = VaultUserConfig.model_validate({"auth": "null"})
        assert isinstance(config, VaultUserConfig)
        assert config.url == Url("https://env.example.com")

    def test_url__teleport(self):
        #  allow None when teleport is set
        config = VaultUserConfig.model_validate(
            {"auth": "null", "teleport": {"app": "test"}}
        )
        assert isinstance(config, VaultUserConfig)
        assert config.url == LazyProvidedMarker.ProvidedByTeleport
        assert config.tls == LazyProvidedMarker.ProvidedByTeleport

    def test_url__missing(self):
        if "VAULT_ADDR" in os.environ:
            pytest.skip("VAULT_ADDR is set. Skipping test.")
        with pytest.raises(ValidationError):
            VaultUserConfig.model_validate({"auth": "null"})

    def test_auth__shortcut(self):
        config = VaultUserConfig.model_validate(
            {"url": "https://example.com", "auth": "null"}
        )
        assert isinstance(config, VaultUserConfig)
        assert config.auth_object == NoAuth()

    def test_auth__default(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("SECRETS_ENV_TOKEN", "tok3n")

        config = VaultUserConfig.model_validate({"url": "https://example.com"})
        assert isinstance(config, VaultUserConfig)
        assert config.auth_object == TokenAuth(token="tok3n")

    def test_auth__invalid(self):
        with pytest.raises(
            ValueError, match="Missing required config <mark>auth method</mark>"
        ):
            VaultUserConfig.model_validate(
                {
                    "url": "https://example.com",
                    "auth": {"foo": "bar"},
                }
            )

    def test_teleport(self, tmp_path: Path):
        (tmp_path / "ca.cert").touch()

        with pytest.warns() as warns:
            config = VaultUserConfig.model_validate(
                {
                    "url": "https://example.com",
                    "auth": "null",
                    "tls": {"ca_cert": str(tmp_path / "ca.cert")},
                    "teleport": {"app": "test"},
                }
            )

        assert config.teleport is not None
        assert config.url == LazyProvidedMarker.ProvidedByTeleport
        assert config.tls == LazyProvidedMarker.ProvidedByTeleport

        assert len(warns) == 2
        assert "Any provided URL would be discarded" in str(warns[0].message)
        assert "TLS configuration would be overlooked" in str(warns[1].message)

    def test_proxy(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("SECRETS_ENV_PROXY", "http://env.proxy.example.com")
        config = VaultUserConfig.model_validate(
            {"url": "https://example.com", "auth": "null"}
        )
        assert isinstance(config, VaultUserConfig)
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
