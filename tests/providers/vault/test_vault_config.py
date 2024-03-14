import os
from pathlib import Path
from unittest.mock import patch

import pytest

import secrets_env.providers.vault.config as t
from secrets_env.providers.vault.auth.base import NullAuth
from secrets_env.providers.vault.config import TlsConfig


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
    def setup_method(self):
        self.data = {"url": "https://example.com", "auth": "null", "tls": {}}

    @pytest.mark.parametrize(
        ("cfg_proxy", "proxy"),
        [
            ({}, None),
            ({"proxy": "http://proxy.example.com"}, "http://proxy.example.com"),
        ],
    )
    @pytest.mark.parametrize(
        ("cfg_ca_cert", "ca_cert"),
        [
            ({}, None),
            ({"ca_cert": "/data/ca.cert"}, Path("/data/ca.cert")),
        ],
    )
    @pytest.mark.parametrize(
        ("cfg_client_cert", "client_cert"),
        [
            ({}, None),
            ({"client_cert": "/data/client.pem"}, Path("/data/client.pem")),
            (
                {"client_cert": "/data/client.pem", "client_key": "/data/client.key"},
                (Path("/data/client.pem"), Path("/data/client.key")),
            ),
        ],
    )
    def test_success(
        self,
        monkeypatch: pytest.MonkeyPatch,
        cfg_proxy,
        proxy,
        cfg_ca_cert,
        ca_cert,
        cfg_client_cert,
        client_cert,
    ):
        if "VAULT_ADDR" in os.environ:
            pytest.skip("VAULT_ADDR is set. Skipping test.")

        monkeypatch.setattr(Path, "is_file", lambda _: True)

        # setup
        self.data.update(cfg_proxy)
        self.data["tls"].update(cfg_ca_cert)
        self.data["tls"].update(cfg_client_cert)

        # run
        cfg = t.get_connection_info(self.data)

        # test
        assert isinstance(cfg, dict)
        assert cfg["url"] == "https://example.com"
        assert cfg["auth"] == NullAuth()

        def _assert_key_equals(key: str, value):
            if value:
                assert cfg[key] == value
            else:
                assert key not in cfg

        _assert_key_equals("proxy", proxy)
        _assert_key_equals("ca_cert", ca_cert)
        _assert_key_equals("client_cert", client_cert)

    def test_fail(self):
        with patch.object(t, "get_url", return_value=None):
            assert t.get_connection_info(self.data) is None

        with patch.object(t, "get_auth", return_value=None):
            assert t.get_connection_info(self.data) is None

        with patch.object(t.TlsConfig, "model_validate", side_effect=TypeError):
            assert t.get_connection_info(self.data) is None

        # make sure the errors above are not caused by malformed data dict
        assert isinstance(t.get_connection_info(self.data), dict)


class TestGetURL:
    @pytest.fixture(autouse=True)
    def _del_env_vars(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.delenv("VAULT_ADDR", raising=False)

    def setup_method(self):
        self.data = {"url": "https://data.example.com"}

    def test_from_data(self):
        assert t.get_url(self.data) == "https://data.example.com"

    @pytest.mark.parametrize("var_name", ["SECRETS_ENV_ADDR", "VAULT_ADDR"])
    def test_from_env(self, monkeypatch: pytest.MonkeyPatch, var_name: str):
        monkeypatch.setenv(var_name, "https://env.example.com")
        assert t.get_url(self.data) == "https://env.example.com"

    def test_missing(self, caplog: pytest.LogCaptureFixture):
        assert t.get_url({}) is None
        assert "Missing required config <mark>url</mark>." in caplog.text

    def test_type_error(self):
        assert t.get_url({"url": 1234}) is None


class TestGetAuthBehavior:
    def test_from_data(self):
        assert isinstance(
            t.get_auth("https://example.com", {"method": "null"}), NullAuth
        )

    def test_syntax_sugar(self):
        assert isinstance(t.get_auth("https://example.com", "null"), NullAuth)

    def test_type_error(self):
        assert t.get_auth("https://example.com", {"method": 1234}) is None

    def test_default_method(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ):
        monkeypatch.setattr(t, "DEFAULT_AUTH_METHOD", "null")

        assert isinstance(t.get_auth("https://example.com", {}), NullAuth)
        assert (
            "Missing required config <mark>auth method</mark>. "
            "Use default method <data>null</data>"
        ) in caplog.text

    def test_unknown_method(self):
        with pytest.raises(ValueError, match="Unknown auth method: no-this-method"):
            t.get_auth("https://example.com", {"method": "no-this-method"})


class TestGetProxy:
    def test_success(self):
        assert t.get_proxy({"proxy": "http://test"}) == ("http://test", True)

    def test_success_env(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("secrets_env_proxy", "http://test")
        assert t.get_proxy({}) == ("http://test", True)

    def test_empty(self):
        assert t.get_proxy({}) == (None, True)
        assert t.get_proxy({"proxy": None}) == (None, True)
        assert t.get_proxy({"proxy": ""}) == (None, True)

    def test_type_error(self):
        assert t.get_proxy({"proxy": 1234}) == (None, False)

    def test_value_error(self, caplog: pytest.LogCaptureFixture):
        assert t.get_proxy({"proxy": "test"}) == (None, False)
        assert "Proxy must specify 'http://' or 'https://' protocol" in caplog.text
