from pathlib import Path
from unittest.mock import Mock

import pytest

import secrets_env.auth
import secrets_env.config.parser as t
from secrets_env.auth import Auth


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


class TestGetAuth:
    @pytest.fixture()
    def _patch_get_auth(self, monkeypatch: pytest.MonkeyPatch):
        def mock_get_auth(method: str, _):
            assert method == "test"
            return Mock(spec=Auth)

        monkeypatch.setattr(secrets_env.auth, "get_auth", mock_get_auth)

    @pytest.mark.usefixtures("_patch_get_auth")
    def test_from_data(self):
        assert isinstance(t.get_auth({"method": "test"}), Auth)

    @pytest.mark.usefixtures("_patch_get_auth")
    def test_from_env(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("SECRETS_ENV_METHOD", "test")
        assert isinstance(t.get_auth({}), Auth)

    @pytest.mark.usefixtures("_patch_get_auth")
    def test_syntax_sugar(self):
        assert isinstance(t.get_auth("test"), Auth)

    def test_type_error(self):
        assert t.get_auth({"method": 1234}) is None

    def test_default_method(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ):
        def mock_get_auth(method: str, _):
            assert method == "token"
            return Mock(spec=Auth)

        monkeypatch.setattr(secrets_env.auth, "get_auth", mock_get_auth)

        assert isinstance(t.get_auth({}), Auth)
        assert (
            "Missing required config <mark>auth method</mark>. "
            "Use default method <data>token</data>"
        ) in caplog.text


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
