from pathlib import Path
from unittest.mock import Mock, patch

import pytest

import secrets_env.providers.vault.config as t
from secrets_env.providers.vault.auth.base import Auth
from secrets_env.providers.vault.auth.null import NoAuth


class TestGetConnectionInfo:
    def setup_method(self):
        self.data = {"url": "https://example.com", "auth": "null", "tls": {}}

    @pytest.mark.usefixtures("_disable_ensure_path_exist_check")
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
    def test_success(self, cfg_ca_cert, ca_cert, cfg_client_cert, client_cert):
        # setup
        self.data["tls"].update(cfg_ca_cert)
        self.data["tls"].update(cfg_client_cert)

        # run
        cfg = t.get_connection_info(self.data)

        # test
        assert isinstance(cfg, dict)
        assert cfg["url"] == "https://example.com"
        assert cfg["auth"] == NoAuth()

        if ca_cert:
            assert cfg["ca_cert"] == ca_cert
        else:
            assert "ca_cert" not in cfg

        if client_cert:
            assert cfg["client_cert"] == client_cert
        else:
            assert "client_cert" not in cfg

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
        assert isinstance(t.get_auth({"method": "null"}), NoAuth)

    def test_from_env(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("SECRETS_ENV_METHOD", "null")
        assert isinstance(t.get_auth({}), NoAuth)

    def test_syntax_sugar(self):
        assert isinstance(t.get_auth("null"), NoAuth)

    def test_type_error(self):
        assert t.get_auth({"method": 1234}) is None

    def test_default_method(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ):
        monkeypatch.setattr(t, "DEFAULT_AUTH_METHOD", "null")

        assert isinstance(t.get_auth({}), NoAuth)
        assert (
            "Missing required config <mark>auth method</mark>. "
            "Use default method <data>null</data>"
        ) in caplog.text

    def test_unknown_method(self, caplog: pytest.LogCaptureFixture):
        assert t.get_auth({"method": "no-this-method"}) is None
        assert "Unknown auth method: <data>no-this-method</data>" in caplog.text


class TestGetAuthFactory:
    def setup_method(self):
        self.mock_auth = Mock(spec=Auth)

    def mock_load(self, data: dict) -> Auth:
        assert isinstance(data, dict)
        return self.mock_auth

    def test_token(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(
            "secrets_env.providers.vault.auth.token.TokenAuth.load", self.mock_load
        )
        assert t.get_auth({"method": "TOKEN"}) is self.mock_auth

    def test_okta(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(
            "secrets_env.providers.vault.auth.userpass.OktaAuth.load", self.mock_load
        )
        assert t.get_auth({"method": "okta"}) is self.mock_auth

    def test_oidc(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(
            "secrets_env.providers.vault.auth.oidc.OpenIDConnectAuth.load",
            self.mock_load,
        )
        assert t.get_auth({"method": "oidc"}) is self.mock_auth

    def test_no_auth(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(
            "secrets_env.providers.vault.auth.null.NoAuth.load", self.mock_load
        )
        assert t.get_auth({"method": "null"}) is self.mock_auth

    def test_basic(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(
            "secrets_env.providers.vault.auth.userpass.BasicAuth.load", self.mock_load
        )
        assert t.get_auth({"method": "Basic"}) is self.mock_auth

    def test_ldap(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(
            "secrets_env.providers.vault.auth.userpass.LDAPAuth.load", self.mock_load
        )
        assert t.get_auth({"method": "LDAP"}) is self.mock_auth

    def test_radius(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(
            "secrets_env.providers.vault.auth.userpass.RADIUSAuth.load", self.mock_load
        )
        assert t.get_auth({"method": "radius"}) is self.mock_auth


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
