import os
from pathlib import Path
from unittest.mock import Mock, PropertyMock, patch

import httpx
import httpx._config
import pytest
import respx

import secrets_env.providers.vault.provider as t
from secrets_env.exceptions import AuthenticationError, ConfigError, ValueNotFound
from secrets_env.providers.vault.auth.base import Auth
from secrets_env.providers.vault.auth.token import TokenAuth


@pytest.fixture()
def mock_client() -> httpx.Client:
    client = Mock(spec=httpx.Client)
    client.headers = {}
    return client


@pytest.fixture()
def mock_auth():
    auth = Mock(spec=Auth)
    auth.method.return_value = "mocked"
    return auth


class TestKvProvider:
    """Unit tests for KvProvider"""

    @pytest.fixture()
    def provider(self, mock_auth: Auth) -> t.KvProvider:
        return t.KvProvider("https://example.com/", mock_auth)

    def test_type(self, provider: t.KvProvider):
        assert provider.type == "vault"

    def test_client_success(
        self,
        monkeypatch: pytest.MonkeyPatch,
        provider: t.KvProvider,
        mock_client: httpx.Client,
    ):
        # setup
        monkeypatch.setattr(t, "get_token", lambda c, a: "token")

        patch_client = Mock(return_value=mock_client)
        monkeypatch.setattr("httpx.Client", patch_client)

        provider.proxy = "proxy"
        provider.ca_cert = Mock(spec=Path)
        provider.client_cert = Mock(spec=Path)

        # run twice for testing cache
        assert provider.client is mock_client
        assert provider.client is mock_client

        # test
        assert mock_client.headers["X-Vault-Token"] == "token"

        _, kwargs = patch_client.call_args
        assert kwargs["base_url"] == "https://example.com/"
        assert kwargs["proxies"] == "proxy"
        assert isinstance(kwargs["verify"], Path)
        assert isinstance(kwargs["cert"], Path)

    @pytest.mark.parametrize("spec", ["foo#bar", {"path": "foo", "field": "bar"}])
    def test_get_success(
        self, monkeypatch: pytest.MonkeyPatch, provider: t.KvProvider, spec
    ):
        def mock_read_field(path, field):
            assert path == "foo"
            assert field == "bar"
            return "secret"

        monkeypatch.setattr(provider, "read_field", mock_read_field)

        assert provider.get(spec) == "secret"

    def test_get_fail(self, provider: t.KvProvider):
        with pytest.raises(ConfigError):
            provider.get({})

        with pytest.raises(TypeError):
            provider.get(1234)

    def test_read_secret_success(
        self,
        monkeypatch: pytest.MonkeyPatch,
        provider: t.KvProvider,
        unittest_client: httpx.Client,
    ):
        monkeypatch.setattr(provider, "_secrets", {})
        monkeypatch.setattr(
            t.KvProvider, "client", PropertyMock(return_value=unittest_client)
        )

        monkeypatch.setattr(t, "read_secret", lambda _1, _2: {"bar": "secret"})
        assert provider.read_secret("test-path") == {"bar": "secret"}

    def test_read_secret_cache(
        self, monkeypatch: pytest.MonkeyPatch, provider: t.KvProvider
    ):
        monkeypatch.setattr(provider, "_secrets", {"test-path": {"bar": "secret"}})
        assert provider.read_secret("test-path") == {"bar": "secret"}

    def test_read_secret_not_found(
        self,
        monkeypatch: pytest.MonkeyPatch,
        provider: t.KvProvider,
        unittest_client: httpx.Client,
    ):
        monkeypatch.setattr(provider, "_secrets", {})
        monkeypatch.setattr(
            t.KvProvider, "client", PropertyMock(return_value=unittest_client)
        )
        monkeypatch.setattr(t, "read_secret", lambda _1, _2: None)
        with pytest.raises(ValueNotFound):
            provider.read_secret("test-secret")

    def test_read_secret_error(self, provider: t.KvProvider):
        with pytest.raises(TypeError):
            provider.read_secret(1234)

    def test_read_field_success(
        self, monkeypatch: pytest.MonkeyPatch, provider: t.KvProvider
    ):
        monkeypatch.setattr(provider, "read_secret", lambda _: {"bar": "secret"})
        assert provider.read_field("foo", "bar") == "secret"

    def test_read_field_fail(
        self, monkeypatch: pytest.MonkeyPatch, provider: t.KvProvider
    ):
        with pytest.raises(TypeError):
            provider.read_field(1234, "bar")

        monkeypatch.setattr(provider, "read_secret", lambda _: {})
        with pytest.raises(ValueNotFound):
            provider.read_field("foo", "bar")


@pytest.mark.integration_test()
class TestKvProviderUsingVaultConnection:
    @pytest.fixture(scope="class")
    def provider(self) -> t.KvProvider:
        return t.KvProvider(
            os.getenv("VAULT_ADDR"), TokenAuth(os.getenv("VAULT_TOKEN"))
        )

    def test_client_success(self, provider: t.KvProvider):
        with patch.object(t, "is_authenticated", return_value=True):
            assert isinstance(provider.client, httpx.Client)
            assert isinstance(provider.client, httpx.Client)  # from cache

    def test_get(self, provider: t.KvProvider):
        assert provider.get("kv1/test#foo") == "hello"
        assert provider.get({"path": "kv2/test", "field": "foo"}) == "hello, world"

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

    def test_read_field(self, provider: t.KvProvider):
        assert provider.read_field("kv1/test", "foo") == "hello"
        assert provider.read_field("kv2/test", 'test."name.with-dot"') == "sample-value"

        with pytest.raises(ValueNotFound):
            provider.read_field("kv2/test", "foo.no-extra-level")
        with pytest.raises(ValueNotFound):
            provider.read_field("kv2/test", "test.no-this-key")
        with pytest.raises(ValueNotFound):
            provider.read_field("secret/no-this-secret", "test")


class TestGetToken:
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


@pytest.mark.integration_test()
def test_is_authenticated():
    # success: use real client
    client = httpx.Client(base_url=os.getenv("VAULT_ADDR"))
    assert t.is_authenticated(client, os.getenv("VAULT_TOKEN"))
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
                    "data": {
                        "options": {"version": "1"},
                        "path": "secrets/",
                        "type": "kv",
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
                    "data": {
                        "options": {"version": "2"},
                        "path": "secrets/",
                        "type": "kv",
                    },
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
