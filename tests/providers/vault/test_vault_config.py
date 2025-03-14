import os
from pathlib import Path
from typing import cast

import pytest
from pydantic import HttpUrl, SecretStr, ValidationError

from secrets_env.providers.vault.auth.base import NoAuth
from secrets_env.providers.vault.auth.token import TokenAuth
from secrets_env.providers.vault.config import (
    AuthConfig,
    LazyProvidedMarker,
    TlsConfig,
    VaultUserConfig,
)


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


class TestAuthConfig:
    def test_success(self):
        config = AuthConfig.model_validate(
            {
                "method": "TEST",
                "role": "SampleRole",
                "username": "User",
            }
        )

        assert config.method == "test"
        assert config.role == "SampleRole"
        assert config.username == "User"

    def test_method(self):
        config = AuthConfig.model_validate("TEST")
        assert config.method == "test"

    def test_role(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("SECRETS_ENV_ROLE", "SampleRole")
        config = AuthConfig.model_validate({"method": "test"})
        assert config.role == "SampleRole"

    def test_username(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("SECRETS_ENV_USERNAME", "User")
        config = AuthConfig.model_validate({"method": "test"})
        assert config.username == "User"


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
        assert config.url == HttpUrl("https://example.com")
        assert config.auth == AuthConfig(method="null")
        assert config.proxy == HttpUrl("http://proxy.example.com")
        assert config.tls == TlsConfig(
            ca_cert=tmp_path / "ca.cert",
            client_cert=tmp_path / "client.pem",
            client_key=tmp_path / "client.key",
        )

    def test_url__envvar(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("SECRETS_ENV_ADDR", "https://env.example.com")
        config = VaultUserConfig.model_validate({"auth": "null"})
        assert isinstance(config, VaultUserConfig)
        assert config.url == HttpUrl("https://env.example.com")

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
        assert config.auth == AuthConfig(method="null")
        assert config.auth_object == NoAuth()

    @pytest.mark.filterwarnings(
        "ignore::UserWarning:secrets_env.providers.vault.config"
    )
    def test_auth__default(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("SECRETS_ENV_TOKEN", "tok3n")

        config = VaultUserConfig.model_validate({"url": "https://example.com"})
        assert isinstance(config, VaultUserConfig)
        assert config.auth_object == TokenAuth(token=cast("SecretStr", "tok3n"))

    def test_auth__invalid(self):
        with pytest.raises(ValidationError) as exc_info:
            VaultUserConfig.model_validate(
                {
                    "url": "https://example.com",
                    "auth": {"foo": "bar"},
                }
            )
        exc_info.match("auth.method")
        exc_info.match("Field required")

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
        assert config.proxy == HttpUrl("http://env.proxy.example.com")
