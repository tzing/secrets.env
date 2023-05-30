from pathlib import Path
from unittest.mock import Mock, patch

import httpx
import httpx._config
import pytest
import respx

import secrets_env.providers.vault.provider as t
from secrets_env.exceptions import AuthenticationError, ConfigError, ValueNotFound
from secrets_env.providers.vault.auth.base import Auth
from secrets_env.providers.vault.auth.token import TokenAuth


@pytest.fixture()
def mock_auth():
    auth = Mock(spec=Auth)
    auth.method.return_value = "mocked"
    return auth


class TestKvProvider1:
    """Unit tests for KvProvider"""

    @pytest.fixture()
    def provider(self, mock_auth: Auth) -> t.KvProvider:
        return t.KvProvider("https://example.com/", mock_auth)

    def test_client_error_1(self, provider: t.KvProvider, mock_auth: Auth):
        mock_auth.login.return_value = None
        with pytest.raises(AuthenticationError):
            provider.client

    def test_client_error_2(self, provider: t.KvProvider, mock_auth: Auth):
        mock_auth.login.return_value = "test-token"
        with pytest.raises(AuthenticationError), patch.object(
            t, "is_authenticated", return_value=False
        ):
            provider.client

    def test_client_error_3(self, provider: t.KvProvider, mock_auth: Auth):
        mock_auth.login.side_effect = httpx.RequestError("test")
        with pytest.raises(httpx.RequestError):
            provider.client

    def test_client_error_4(self, provider: t.KvProvider, mock_auth: Auth):
        mock_auth.login.side_effect = httpx.ProxyError("test")
        with pytest.raises(AuthenticationError):
            provider.client


class TestKvProvider2:
    """Integration tests for KvProvider"""

    @pytest.fixture(scope="class")
    def provider(self) -> t.KvProvider:
        return t.KvProvider("http://localhost:8200", TokenAuth("!ntegr@t!0n-test"))

    def test_client_success(self, provider: t.KvProvider):
        with patch.object(t, "is_authenticated", return_value=True):
            assert isinstance(provider.client, httpx.Client)
            assert isinstance(provider.client, httpx.Client)  # from cache

    def test_get(self, provider: t.KvProvider):
        assert provider.get("kv1/test#foo") == "hello"
        assert provider.get({"path": "kv2/test", "field": "foo"}) == "hello, world"

        with pytest.raises(ConfigError):
            provider.get("")
        with pytest.raises(TypeError):
            provider.get(1234)

    def test_read_secret_v1(self, provider: t.KvProvider):
        secret_1 = provider.read_secret("kv1/test")
        assert isinstance(secret_1, dict)
        assert secret_1["foo"] == "hello"

        secret_2 = provider.read_secret("kv1/test")
        assert secret_1 is secret_2

    def test_read_secret_v2(self, provider: t.KvProvider):
        secret = provider.read_secret("kv2/test")
        assert isinstance(secret, dict)
        assert secret["foo"] == "hello, world"

    def test_read_secret_fail(self, provider: t.KvProvider):
        with pytest.raises(ValueNotFound):
            provider.read_secret("no-this-secret")

    def test_read_field(self, provider: t.KvProvider):
        assert provider.read_field("kv1/test", "foo") == "hello"
        assert provider.read_field("kv2/test", 'test."name.with-dot"') == "sample-value"

        with pytest.raises(ValueNotFound):
            provider.read_field("kv2/test", "foo.no-extra-level")
        with pytest.raises(ValueNotFound):
            provider.read_field("kv2/test", "test.no-this-key")
        with pytest.raises(ValueNotFound):
            provider.read_field("secret/no-this-secret", "test")

        with pytest.raises(TypeError):
            provider.read_field(1234, "foo")
        with pytest.raises(TypeError):
            provider.read_field("secret/test", 1234)


class TestCreateClient:
    fake_pem = Path("/data/fake.pem")

    @pytest.mark.parametrize("ca_cert", [fake_pem, None])
    @pytest.mark.parametrize("client_cert", [fake_pem, (fake_pem, fake_pem), None])
    def test_success(self, ca_cert, client_cert):
        with patch.object(
            httpx._config.SSLConfig, "load_ssl_context_verify", return_value=None
        ):
            client = t.create_client("http://example.com", ca_cert, client_cert)

        assert isinstance(client, httpx.Client)

    def test_type_error(self):
        with pytest.raises(TypeError):
            t.create_client(1234, None, None)
        with pytest.raises(TypeError):
            t.create_client("http://example.com", 1234, None)
        with pytest.raises(TypeError):
            t.create_client("http://example.com", None, 1234)


class TestGetToken:
    @pytest.fixture()
    def mock_client(self) -> httpx.Client:
        return Mock(spec=httpx.Client)

    def test_success(
        self,
        mock_client: httpx.Client,
        mock_auth: Auth,
        monkeypatch: pytest.MonkeyPatch,
    ):
        mock_auth.login.return_value = "t0ken"
        monkeypatch.setattr(t, "is_authenticated", lambda c, t: True)
        assert t.get_token(mock_client, mock_auth) == "t0ken"

    def test_no_token(self, mock_client: httpx.Client, mock_auth: Auth):
        mock_auth.login.return_value = None
        with pytest.raises(AuthenticationError, match="Absence of token information"):
            t.get_token(mock_client, mock_auth)

    def test_not_authenticated(
        self,
        mock_client: httpx.Client,
        mock_auth: Auth,
        monkeypatch: pytest.MonkeyPatch,
    ):
        mock_auth.login.return_value = "t0ken"
        monkeypatch.setattr(t, "is_authenticated", lambda c, t: False)
        with pytest.raises(AuthenticationError, match="Invalid token"):
            t.get_token(mock_client, mock_auth)

    def test_login_connection_error(self, mock_client: httpx.Client, mock_auth: Auth):
        mock_auth.login.side_effect = httpx.ProxyError("test")
        with pytest.raises(
            AuthenticationError, match="Encounter proxy error while retrieving token"
        ):
            t.get_token(mock_client, mock_auth)

    def test_login_exception(self, mock_client: httpx.Client, mock_auth: Auth):
        mock_auth.login.side_effect = httpx.HTTPError("test")
        with pytest.raises(httpx.HTTPError):
            t.get_token(mock_client, mock_auth)


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


class TestReadSecret:
    @pytest.fixture()
    def patch_get_mount_point(self):
        with patch.object(t, "get_mount_point", return_value=("secrets/", 1)) as p:
            yield p

    @pytest.mark.usefixtures("patch_get_mount_point")
    def test_kv1(self, respx_mock: respx.MockRouter, unittest_client: httpx.Client):
        respx_mock.get("https://example.com/v1/secrets/test").mock(
            httpx.Response(
                200,
                json={
                    "request_id": "a8f28d97-8a9d-c9dd-4d86-e815083b33ad",
                    "lease_id": "",
                    "renewable": False,
                    "lease_duration": 2764800,
                    "data": {"test": "mock"},
                    "wrap_info": None,
                    "warnings": None,
                    "auth": None,
                },
            )
        )

        with patch.object(t, "get_mount_point", return_value=("secrets/", 1)):
            assert t.read_secret(unittest_client, "secrets/test") == {"test": "mock"}

    def test_kv2(
        self,
        respx_mock: respx.MockRouter,
        unittest_client: httpx.Client,
        patch_get_mount_point: Mock,
    ):
        respx_mock.get("https://example.com/v1/secrets/data/test").mock(
            httpx.Response(
                200,
                json={
                    "request_id": "9ababbb6-3749-cf2c-5a5b-85660e917e8e",
                    "lease_id": "",
                    "renewable": False,
                    "lease_duration": 0,
                    "data": {
                        "data": {"test": "mock"},
                        "metadata": {
                            "created_time": "2022-09-20T15:57:45.143053836Z",
                            "custom_metadata": None,
                            "deletion_time": "",
                            "destroyed": False,
                            "version": 1,
                        },
                    },
                    "wrap_info": None,
                    "warnings": None,
                    "auth": None,
                },
            )
        )

        patch_get_mount_point.return_value = ("secrets/", 2)
        assert t.read_secret(unittest_client, "secrets/test") == {"test": "mock"}

    def test_get_mount_point_error(
        self, unittest_client: httpx.Client, patch_get_mount_point: Mock
    ):
        patch_get_mount_point.return_value = (None, None)
        assert t.read_secret(unittest_client, "secrets/test") is None

    @pytest.mark.usefixtures("patch_get_mount_point")
    def test_connection_error(
        self,
        respx_mock: respx.MockRouter,
        unittest_client: httpx.Client,
        caplog: pytest.LogCaptureFixture,
    ):
        respx_mock.get("https://example.com/v1/secrets/test").mock(
            side_effect=httpx.ProxyError
        )

        assert t.read_secret(unittest_client, "secrets/test") is None
        assert (
            "Error occurred during query secret secrets/test: proxy error"
            in caplog.text
        )

    @pytest.mark.usefixtures("patch_get_mount_point")
    def test_unhandled_exception(
        self, respx_mock: respx.MockRouter, unittest_client: httpx.Client
    ):
        respx_mock.get("https://example.com/v1/secrets/test").mock(
            side_effect=httpx.DecodingError
        )
        with pytest.raises(httpx.DecodingError):
            t.read_secret(unittest_client, "secrets/test")

    @pytest.mark.usefixtures("patch_get_mount_point")
    def test_not_found(
        self,
        respx_mock: respx.MockRouter,
        unittest_client: httpx.Client,
        caplog: pytest.LogCaptureFixture,
    ):
        respx_mock.get("https://example.com/v1/secrets/test").mock(httpx.Response(404))
        assert t.read_secret(unittest_client, "secrets/test") is None
        assert "Secret <data>secrets/test</data> not found" in caplog.text

    @pytest.mark.usefixtures("patch_get_mount_point")
    def test_bad_request(
        self,
        respx_mock: respx.MockRouter,
        unittest_client: httpx.Client,
        caplog: pytest.LogCaptureFixture,
    ):
        respx_mock.get("https://example.com/v1/secrets/test").mock(httpx.Response(499))
        assert t.read_secret(unittest_client, "secrets/test") is None
        assert "Error occurred during query secret secrets/test" in caplog.text

    def test_type_error(self):
        with pytest.raises(TypeError):
            t.read_secret(1234, "secrets/test")
        with pytest.raises(TypeError):
            t.read_secret(Mock(spec=httpx.Client), 1234)


def test_split_field():
    assert t.split_field("aa") == ["aa"]
    assert t.split_field("aa.bb") == ["aa", "bb"]
    assert t.split_field('aa."bb.cc"') == ["aa", "bb.cc"]
    assert t.split_field('"aa.bb".cc') == ["aa.bb", "cc"]
    assert t.split_field('"aa.bb"') == ["aa.bb"]

    with pytest.raises(ValueError, match=r"Failed to parse name: "):
        t.split_field("")
    with pytest.raises(ValueError, match=r"Failed to parse name: .+"):
        t.split_field(".")
    with pytest.raises(ValueError, match=r"Failed to parse name: .+"):
        t.split_field("aa.")
    with pytest.raises(ValueError, match=r"Failed to parse name: .+"):
        t.split_field(".aa")


class TestGetSecretSourceStr:
    def test_success(self):
        assert t.get_secret_source_str("foo#bar") == ("foo", "bar")
        assert t.get_secret_source_str("foo#b") == ("foo", "b")
        assert t.get_secret_source_str("f#bar") == ("f", "bar")

    @pytest.mark.parametrize(
        ("input_", "err_msg"),
        [
            ("foo", "Missing delimiter '#'"),
            ("#bar", "Missing secret path"),
            ("foo#", "Missing secret field"),
        ],
    )
    def test_fail(self, input_: str, err_msg: str):
        with pytest.raises(ConfigError, match=err_msg):
            t.get_secret_source_str(input_)


class TestGetSecretSourceDict:
    def test_success(self):
        out = t.get_secret_source_dict({"path": "foo", "field": "bar"})
        assert out == ("foo", "bar")

    @pytest.mark.parametrize(
        ("input_", "err_msg"),
        [
            ({"field": "bar"}, "Missing secret path"),
            ({"path": "foo", "field": 1234}, "Expect str for secret field"),
            ({"path": "foo"}, "Missing secret field"),
            ({"path": 1234, "field": "bar"}, "Expect str for secret path"),
        ],
    )
    def test_fail(self, caplog: pytest.LogCaptureFixture, input_, err_msg: str):
        with pytest.raises((ConfigError, TypeError), match=err_msg):
            t.get_secret_source_dict(input_)
