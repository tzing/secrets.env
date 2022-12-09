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


class TestGetMountPoint:
    @pytest.fixture()
    def route(self, respx_mock: respx.MockRouter):
        return respx_mock.get(
            "https://example.com/v1/sys/internal/ui/mounts/secrets/test"
        )

    def test_success_kv1(self, route: respx.Route, unittest_client: httpx.Client):
        route.mock(
            httpx.Response(
                200,
                json={
                    "request_id": "01eef618-15b2-0445-4768-fae2f953e25d",
                    "lease_id": "",
                    "renewable": False,
                    "lease_duration": 0,
                    "data": {
                        "accessor": "kv_92250a43",
                        "config": {
                            "default_lease_ttl": 0,
                            "force_no_cache": False,
                            "max_lease_ttl": 0,
                        },
                        "description": "",
                        "external_entropy_access": False,
                        "local": False,
                        "options": {"version": "1"},
                        "path": "secrets/",
                        "seal_wrap": False,
                        "type": "kv",
                        "uuid": "f26f43ad-5e58-c739-be4a-a6fb29481bc0",
                    },
                    "wrap_info": None,
                    "warnings": None,
                    "auth": None,
                },
            )
        )
        assert t.get_mount_point(unittest_client, "secrets/test") == ("secrets/", 1)

    def test_success_kv2(self, route: respx.Route, unittest_client: httpx.Client):
        route.mock(
            httpx.Response(
                200,
                json={
                    "request_id": "989b476f-1f1d-c493-0777-8f7e9823a3c8",
                    "lease_id": "",
                    "renewable": False,
                    "lease_duration": 0,
                    "data": {
                        "accessor": "kv_8e4430be",
                        "config": {
                            "default_lease_ttl": 0,
                            "force_no_cache": False,
                            "max_lease_ttl": 0,
                        },
                        "description": "",
                        "external_entropy_access": False,
                        "local": False,
                        "options": {"version": "2"},
                        "path": "secrets/",
                        "seal_wrap": False,
                        "type": "kv",
                        "uuid": "1dc09fc2-4844-f332-b08d-845fcb754545",
                    },
                    "wrap_info": None,
                    "warnings": None,
                    "auth": None,
                },
            )
        )
        assert t.get_mount_point(unittest_client, "secrets/test") == ("secrets/", 2)

    def test_success_legacy(self, route: respx.Route, unittest_client: httpx.Client):
        route.mock(httpx.Response(404))
        assert t.get_mount_point(unittest_client, "secrets/test") == ("", 1)

    def test_not_ported_version(
        self, route: respx.Route, unittest_client: httpx.Client
    ):
        route.mock(
            httpx.Response(
                200,
                json={
                    "data": {
                        "path": "mock/",
                        "type": "kv",
                        "options": {"version": "99"},
                    }
                },
            )
        )
        assert t.get_mount_point(unittest_client, "secrets/test") == (None, None)

    def test_bad_request(
        self,
        route: respx.Route,
        unittest_client: httpx.Client,
        caplog: pytest.LogCaptureFixture,
    ):
        route.mock(httpx.Response(400))
        assert t.get_mount_point(unittest_client, "secrets/test") == (None, None)
        assert "Error occurred during checking metadata for secrets/test" in caplog.text

    def test_connection_error(
        self,
        route: respx.Route,
        unittest_client: httpx.Client,
        caplog: pytest.LogCaptureFixture,
    ):
        route.mock(side_effect=httpx.ConnectError)
        assert t.get_mount_point(unittest_client, "secrets/test") == (None, None)
        assert (
            "Error occurred during checking metadata for secrets/test: connection error"
            in caplog.text
        )

    def test_unhandled_exception(
        self, route: respx.Route, unittest_client: httpx.Client
    ):
        route.mock(side_effect=httpx.DecodingError)
        with pytest.raises(httpx.DecodingError):
            t.get_mount_point(unittest_client, "secrets/test")

    def test_type_error(self):
        with pytest.raises(TypeError):
            t.get_mount_point(1234, "secrets/test")
        with pytest.raises(TypeError):
            t.get_mount_point(Mock(spec=httpx.Client), 1234)
