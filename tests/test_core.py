from pathlib import Path
from unittest.mock import Mock, patch

import httpx
import httpx._config
import pytest

import secrets_env.auth
import secrets_env.core as t
from secrets_env.exception import AuthenticationError


class TestKVReader:
    def setup_method(self):
        self.auth = Mock(spec=secrets_env.auth.Auth)
        self.auth.method.return_value = "mocked"

    def test___init__type_errors(self):
        with pytest.raises(TypeError):
            t.KVReader(1234, self.auth)
        with pytest.raises(TypeError):
            t.KVReader("https://example.com", 1234)
        with pytest.raises(TypeError):
            t.KVReader("https://example.com", self.auth, ca_cert="/path/cert")
        with pytest.raises(TypeError):
            t.KVReader("https://example.com", self.auth, client_cert="/path/cert")
        with pytest.raises(TypeError):
            t.KVReader("https://example.com", self.auth, client_key="/path/cert")

    def test_client(self):
        reader = t.KVReader(url="https://example.com/", auth=self.auth)

        # fail
        self.auth.login.return_value = None
        with pytest.raises(AuthenticationError):
            reader.client

        self.auth.login.return_value = "test-token"
        with pytest.raises(AuthenticationError), patch.object(
            t, "is_authenticated", return_value=False
        ):
            reader.client

        # success
        with patch.object(t, "is_authenticated", return_value=True):
            assert isinstance(reader.client, httpx.Client)
            assert isinstance(reader.client, httpx.Client)  # from cache


def test_create_client(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    # disable cert format check
    monkeypatch.setattr(
        httpx._config.SSLConfig, "load_ssl_context_verify", lambda _: None
    )

    path = tmp_path / "test.pem"

    # no error could be enough
    t.create_client("http://example.com", None, None, None)
    t.create_client("http://example.com", path, None, None)
    t.create_client("http://example.com", path, path, None)
    t.create_client("http://example.com", path, path, path)


def test_is_authenticated():
    # use real client
    client = httpx.Client(base_url="http://localhost:8200")
    assert t.is_authenticated(client, "!ntegr@t!0n-test")
    assert not t.is_authenticated(client, "invalid-token")
