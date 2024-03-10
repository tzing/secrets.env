import os
from pathlib import Path
from unittest.mock import patch

import pytest

import secrets_env.providers.vault.config as t
from secrets_env.providers.vault.auth.base import NullAuth


class TestGetConnectionInfo:
    def setup_method(self):
        self.data = {"url": "https://example.com", "auth": "null", "tls": {}}

    @pytest.mark.usefixtures("_disable_ensure_path_exist_check")
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
        self, cfg_proxy, proxy, cfg_ca_cert, ca_cert, cfg_client_cert, client_cert
    ):
        if "VAULT_ADDR" in os.environ:
            pytest.skip("VAULT_ADDR is set. Skipping test.")

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

        with patch.object(t, "get_tls_ca_cert", return_value=(None, False)):
            assert t.get_connection_info(self.data) is None

        with patch.object(t, "get_tls_client_cert", return_value=(None, False)):
            assert t.get_connection_info(self.data) is None

        # make sure the errors above are not caused by malformed data dict
        assert isinstance(t.get_connection_info(self.data), dict)


class TestGetURL:
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


class TestGetTLS:
    def test_get_tls_ca_cert(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
        path = tmp_path / "ca.cert"
        path.touch()

        # success
        with monkeypatch.context() as ctx:
            ctx.setenv("SECRETS_ENV_CA_CERT", str(path))
            assert t.get_tls_ca_cert({}) == (path, True)

        assert t.get_tls_ca_cert({"ca_cert": str(path)}) == (path, True)

        assert t.get_tls_ca_cert({}) == (None, True)

        # fail
        with monkeypatch.context() as ctx:
            ctx.setenv("SECRETS_ENV_CA_CERT", "/data/no-this-file")
            assert t.get_tls_ca_cert({}) == (None, False)

    def test_get_tls_client_cert(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        caplog: pytest.LogCaptureFixture,
    ):
        client_cert = tmp_path / "client.pem"
        client_cert.touch()

        client_key = tmp_path / "client.key"
        client_key.touch()

        # success: from env var
        with monkeypatch.context() as ctx:
            ctx.setenv("SECRETS_ENV_CLIENT_CERT", str(client_cert))
            assert t.get_tls_client_cert({}) == (client_cert, True)

        # success: from config
        assert t.get_tls_client_cert(
            {
                "client_cert": str(client_cert),
                "client_key": str(client_key),
            }
        ) == ((client_cert, client_key), True)

        # success: no data
        assert t.get_tls_client_cert({}) == (None, True)

        # fail: only key
        with monkeypatch.context() as ctx:
            ctx.setenv("SECRETS_ENV_CLIENT_KEY", str(client_key))
            assert t.get_tls_client_cert({}) == (None, False)
            assert "Missing config <mark>client_cert</mark>." in caplog.text

        # fail: file not exist
        assert t.get_tls_client_cert(
            {
                "client_cert": "/data/no-this-file",
            }
        ) == (None, False)
