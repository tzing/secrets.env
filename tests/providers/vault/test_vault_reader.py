from pathlib import Path
from unittest.mock import Mock, patch

import httpx
import httpx._config
import pytest
import respx

import secrets_env.providers.vault.reader as t
from secrets_env.exceptions import AuthenticationError
from secrets_env.providers.vault.auth.base import Auth
from secrets_env.providers.vault.auth.token import TokenAuth


class TestVaultReader:
    @pytest.fixture(scope="class")
    def real_reader(self) -> t.KVReader:
        return t.KVReader("http://localhost:8200", TokenAuth("!ntegr@t!0n-test"))

    @pytest.fixture()
    def mock_auth(self):
        auth = Mock(spec=Auth)
        auth.method.return_value = "mocked"
        return auth

    @pytest.fixture()
    def mock_reader(self, mock_auth: Auth) -> t.KVReader:
        return t.KVReader("https://example.com/", mock_auth)

    def test_client_success(self, real_reader: t.KVReader):
        with patch.object(t, "is_authenticated", return_value=True):
            assert isinstance(real_reader.client, httpx.Client)
            assert isinstance(real_reader.client, httpx.Client)  # from cache

    def test_client_error_1(self, mock_reader: t.KVReader, mock_auth: Auth):
        mock_auth.login.return_value = None
        with pytest.raises(AuthenticationError):
            mock_reader.client

    def test_client_error_2(self, mock_reader: t.KVReader, mock_auth: Auth):
        mock_auth.login.return_value = "test-token"
        with pytest.raises(AuthenticationError), patch.object(
            t, "is_authenticated", return_value=False
        ):
            mock_reader.client


class TestCreateClient:
    def test_success(self, monkeypatch: pytest.MonkeyPatch):
        # disable cert format check
        monkeypatch.setattr(
            httpx._config.SSLConfig, "load_ssl_context_verify", lambda _: None
        )

        path = Path("/data/fake.pem")

        # no error could be enough
        t.create_client("http://example.com", None, None)
        t.create_client("http://example.com", path, None)
        t.create_client("http://example.com", path, path)
        t.create_client("http://example.com", path, (path, path))

    def test_type_error(self):
        with pytest.raises(TypeError):
            t.create_client(1234, None, None)
        with pytest.raises(TypeError):
            t.create_client("http://example.com", 1234, None)
        with pytest.raises(TypeError):
            t.create_client("http://example.com", None, 1234)


def test_is_authenticated():
    # success: use real client
    client = httpx.Client(base_url="http://localhost:8200")
    assert t.is_authenticated(client, "!ntegr@t!0n-test")
    assert not t.is_authenticated(client, "invalid-token")

    # type error
    with pytest.raises(TypeError):
        t.is_authenticated("http://example.com", "token")
    with pytest.raises(TypeError):
        t.is_authenticated(client, 1234)
