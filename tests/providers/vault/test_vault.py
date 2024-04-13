import os
from pathlib import Path
from unittest.mock import Mock, PropertyMock

import httpx
import pytest
import respx
from pydantic_core import ValidationError, Url

from secrets_env.exceptions import AuthenticationError, NoValue
from secrets_env.provider import Request
from secrets_env.providers.teleport.config import (
    TeleportConnectionParameter,
    TeleportUserConfig,
)
from secrets_env.providers.vault import (
    MountMetadata,
    VaultKvProvider,
    VaultPath,
    _split_field_str,
    create_http_client,
    get_mount,
    get_token,
    is_authenticated,
    read_secret,
)
from secrets_env.providers.vault.auth.base import Auth, NoAuth
from secrets_env.providers.vault.config import TlsConfig, VaultUserConfig


@pytest.fixture()
def intl_provider() -> VaultKvProvider:
    if "VAULT_ADDR" not in os.environ:
        raise pytest.skip("VAULT_ADDR is not set")
    if "VAULT_TOKEN" not in os.environ:
        raise pytest.skip("VAULT_TOKEN is not set")
    return VaultKvProvider(auth="token")


@pytest.fixture()
def intl_client(intl_provider: VaultKvProvider) -> httpx.Client:
    return intl_provider.client


class TestVaultPath:
    @pytest.mark.parametrize(
        "req",
        [
            Request(name="test", value='foo#"bar.baz".qux'),
            Request(name="test", path="foo", field='"bar.baz".qux'),
            Request(name="test", path="foo", field=["bar.baz", "qux"]),
        ],
    )
    def test_success(self, req: Request):
        path = VaultPath.model_validate(req.model_dump())
        assert path == VaultPath(path="foo", field=("bar.baz", "qux"))
        assert str(path) == 'foo#"bar.baz".qux'

    def test_invalid(self):
        # missing path
        with pytest.raises(ValidationError):
            VaultPath(path="", field=("b"))

        # missing path/field separator
        with pytest.raises(ValidationError):
            VaultPath.model_validate(Request(value="foobar"))

        # too many path/field separator
        with pytest.raises(ValidationError):
            VaultPath.model_validate(Request(value="foo#bar#baz"))

        # empty field subpath
        with pytest.raises(ValidationError):
            VaultPath(path="a", field=())
        with pytest.raises(ValidationError):
            VaultPath(path="a", field=("b", "", "c"))
        with pytest.raises(ValidationError):
            VaultPath(path="a", field=("b", ""))


class TestSplitFieldStr:
    def test_success(self):
        assert list(_split_field_str("foo")) == ["foo"]
        assert list(_split_field_str("foo.bar.baz")) == ["foo", "bar", "baz"]
        assert list(_split_field_str('foo."bar.baz"')) == ["foo", "bar.baz"]
        assert list(_split_field_str('"foo.bar".baz')) == ["foo.bar", "baz"]
        assert list(_split_field_str("")) == []

    def test_invalid(self):
        with pytest.raises(ValueError, match=r"Failed to parse field:"):
            list(_split_field_str('foo."bar.baz'))


class TestVaultKvProvider:
    def test_client(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(
            "secrets_env.providers.vault.create_http_client",
            lambda _: Mock(httpx.Client, headers={}),
        )
        provider = VaultKvProvider(url="https://vault.example.com", auth="null")
        assert isinstance(provider.client, httpx.Client)

    def test_client__with_teleport(self, monkeypatch: pytest.MonkeyPatch):
        def mock_create_http_client(config: VaultUserConfig):
            assert config.url == Url("https://vault.teleport.example.com/")
            assert config.teleport is None
            assert config.tls.ca_cert is None
            assert config.tls.client_cert == Path("/mock/client.pem")
            assert config.tls.client_key == Path("/mock/client.key")

            client = Mock(httpx.Client)
            client.headers = {}
            return client

        monkeypatch.setattr(
            "secrets_env.providers.vault.create_http_client", mock_create_http_client
        )

        teleport_user_config = Mock(TeleportUserConfig)
        teleport_user_config.connection_param = Mock(
            TeleportConnectionParameter,
            uri="https://vault.teleport.example.com",
            path_ca=None,
            path_cert=Path("/mock/client.pem"),
            path_key=Path("/mock/client.key"),
        )

        provider = VaultKvProvider(auth="null", teleport=teleport_user_config)
        client = provider.client
        assert isinstance(client, httpx.Client)

    @pytest.fixture()
    def unittest_provider(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(
            VaultKvProvider, "client", PropertyMock(return_value=Mock(httpx.Client))
        )
        return VaultKvProvider(url="https://vault.example.com", auth="null")

    def test_get_value__success(
        self, monkeypatch: pytest.MonkeyPatch, unittest_provider: VaultKvProvider
    ):
        monkeypatch.setattr(
            VaultKvProvider, "_read_secret", Mock(return_value={"bar": "test"})
        )
        assert (
            unittest_provider({"name": "test", "path": "foo", "field": "bar"}) == "test"
        )

    def test_get_value__too_depth(
        self,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
        unittest_provider: VaultKvProvider,
    ):
        monkeypatch.setattr(
            VaultKvProvider, "_read_secret", Mock(return_value={"bar": "test"})
        )
        with pytest.raises(NoValue):
            unittest_provider({"name": "test", "path": "foo", "field": "bar.baz"})
        assert 'Field "bar.baz" not found in "foo"' in caplog.text

    def test_get_value__too_shallow(
        self,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
        unittest_provider: VaultKvProvider,
    ):
        monkeypatch.setattr(
            VaultKvProvider, "_read_secret", Mock(return_value={"bar": {"baz": "test"}})
        )
        with pytest.raises(NoValue):
            unittest_provider({"name": "test", "path": "foo", "field": "bar"})
        assert 'Field "bar" in "foo" is not point to a string value' in caplog.text

    def test_read_secret__success(
        self, monkeypatch: pytest.MonkeyPatch, unittest_provider: VaultKvProvider
    ):
        func = Mock(return_value={"foo": "bar"})
        monkeypatch.setattr("secrets_env.providers.vault.read_secret", func)

        path = VaultPath(path="foo", field="bar")
        assert unittest_provider._read_secret(path) == {"foo": "bar"}
        assert unittest_provider._read_secret(path) == {"foo": "bar"}

        assert func.call_count == 1

        client, path = func.call_args[0]
        assert isinstance(client, httpx.Client)
        assert path == "foo"

    def test_read_secret__not_found(
        self, monkeypatch: pytest.MonkeyPatch, unittest_provider: VaultKvProvider
    ):
        func = Mock(return_value=None)
        monkeypatch.setattr("secrets_env.providers.vault.read_secret", func)

        path = VaultPath(path="foo", field="bar")
        with pytest.raises(LookupError):
            unittest_provider._read_secret(path)
        with pytest.raises(LookupError):
            unittest_provider._read_secret(path)

        assert func.call_count == 1

    def test_integration(self, intl_provider: VaultKvProvider):
        assert (
            intl_provider({"name": "test", "path": "kv2/test", "field": "foo"})
            == "hello, world"
        )
        assert (
            intl_provider({"name": "test", "value": 'kv2/test#test."name.with-dot"'})
            == "sample-value"
        )


class TestCreateHttpClient:
    @pytest.mark.skipif("VAULT_ADDR" in os.environ, reason="VAULT_ADDR is set")
    def test_basic(self):
        config = VaultUserConfig(
            url="https://vault.example.com",
            auth="null",
        )

        client = create_http_client(config)

        assert isinstance(client, httpx.Client)
        assert client.base_url == httpx.URL("https://vault.example.com/")

    def test_proxy(self):
        config = VaultUserConfig(
            url="https://vault.example.com",
            auth="null",
            proxy="http://proxy.example.com",
        )

        client = create_http_client(config)
        assert isinstance(client, httpx.Client)

    @pytest.fixture()
    def mock_httpx_client(self, monkeypatch: pytest.MonkeyPatch):
        client = Mock(httpx.Client)
        monkeypatch.setattr("httpx.Client", client)
        return client

    def test_ca(self, mock_httpx_client: Mock):
        config = VaultUserConfig(
            url="https://vault.example.com",
            auth="null",
            tls=Mock(
                TlsConfig,
                ca_cert=Path("/mock/ca.pem"),
                client_cert=None,
                client_key=None,
            ),
        )

        create_http_client(config)

        _, kwargs = mock_httpx_client.call_args
        assert kwargs["verify"] == Path("/mock/ca.pem")

    def test_client_cert(self, mock_httpx_client: Mock):
        config = VaultUserConfig(
            url="https://vault.example.com",
            auth="null",
            tls=Mock(
                TlsConfig,
                ca_cert=None,
                client_cert=Path("/mock/client.pem"),
                client_key=None,
            ),
        )

        create_http_client(config)

        _, kwargs = mock_httpx_client.call_args
        assert kwargs["cert"] == Path("/mock/client.pem")

    def test_client_cert_pair(self, mock_httpx_client: Mock):
        config = VaultUserConfig(
            url="https://vault.example.com",
            auth="null",
            tls=Mock(
                TlsConfig,
                ca_cert=None,
                client_cert=Path("/mock/client.pem"),
                client_key=Path("/mock/client.key"),
            ),
        )

        create_http_client(config)

        _, kwargs = mock_httpx_client.call_args
        assert kwargs["cert"] == (Path("/mock/client.pem"), Path("/mock/client.key"))


class TestGetToken:
    def test_success(self, monkeypatch: pytest.MonkeyPatch):
        client = Mock(httpx.Client)
        auth = NoAuth(token="t0ken")
        monkeypatch.setattr(
            "secrets_env.providers.vault.is_authenticated", lambda c, t: True
        )
        assert get_token(client, auth) == "t0ken"

    def test_authenticate_fail(self, monkeypatch: pytest.MonkeyPatch):
        client = Mock(httpx.Client)
        auth = NoAuth(token="t0ken")
        monkeypatch.setattr(
            "secrets_env.providers.vault.is_authenticated", lambda c, t: False
        )
        with pytest.raises(AuthenticationError, match="Invalid token"):
            get_token(client, auth)

    def test_login_connection_error(self):
        client = Mock(httpx.Client)
        auth = Mock(Auth)
        auth.login.side_effect = httpx.ProxyError("test")
        with pytest.raises(
            AuthenticationError, match="Encounter proxy error while retrieving token"
        ):
            get_token(client, auth)

    def test_login_exception(self):
        client = Mock(httpx.Client)
        auth = Mock(Auth)
        auth.login.side_effect = httpx.HTTPError("test")
        with pytest.raises(httpx.HTTPError):
            get_token(client, auth)


class TestIsAuthenticated:

    def test_success(self, respx_mock: respx.MockRouter):
        respx_mock.get("https://vault.example.com/v1/auth/token/lookup-self")

        client = httpx.Client(base_url="https://vault.example.com")
        assert is_authenticated(client, "test-token") is True

    def test_fail(self, respx_mock: respx.MockRouter):
        respx_mock.get("https://vault.example.com/v1/auth/token/lookup-self").respond(
            status_code=403,
            json={"errors": ["mock permission denied"]},
        )

        client = httpx.Client(base_url="https://vault.example.com")
        assert is_authenticated(client, "test-token") is False

    def test_integration(self):
        if "VAULT_ADDR" not in os.environ:
            raise pytest.skip("VAULT_ADDR is not set")
        if "VAULT_TOKEN" not in os.environ:
            raise pytest.skip("VAULT_TOKEN is not set")

        client = httpx.Client(base_url=os.getenv("VAULT_ADDR"))

        assert is_authenticated(client, os.getenv("VAULT_TOKEN")) is True
        assert is_authenticated(client, "invalid-token") is False


class TestReadSecret:
    @pytest.fixture()
    def _set_mount_kv2(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(
            "secrets_env.providers.vault.get_mount",
            lambda c, p: MountMetadata(path="secrets/", version=2),
        )

    @pytest.mark.usefixtures("_set_mount_kv2")
    def test_kv2(
        self,
        respx_mock: respx.MockRouter,
        unittest_client: httpx.Client,
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

        assert read_secret(unittest_client, "secrets/test") == {"test": "mock"}

    def test_kv2_integration(self, intl_client: httpx.Client):
        assert read_secret(intl_client, "kv2/test") == {
            "foo": "hello, world",
            "test": {"name.with-dot": "sample-value"},
        }

    def test_kv1(
        self,
        monkeypatch: pytest.MonkeyPatch,
        respx_mock: respx.MockRouter,
        unittest_client: httpx.Client,
    ):
        monkeypatch.setattr(
            "secrets_env.providers.vault.get_mount",
            lambda c, p: MountMetadata(path="secrets/", version=1),
        )
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

        assert read_secret(unittest_client, "secrets/test") == {"test": "mock"}

    def test_kv1_integration(self, intl_client: httpx.Client):
        assert read_secret(intl_client, "kv1/test") == {"foo": "hello"}

    @pytest.mark.usefixtures("_set_mount_kv2")
    def test_not_found(
        self,
        respx_mock: respx.MockRouter,
        unittest_client: httpx.Client,
        caplog: pytest.LogCaptureFixture,
    ):
        respx_mock.get("https://example.com/v1/secrets/data/test").mock(
            httpx.Response(404)
        )
        assert read_secret(unittest_client, "secrets/test") is None
        assert "Secret <data>secrets/test</data> not found" in caplog.text

    def test_get_mount_error(
        self, monkeypatch: pytest.MonkeyPatch, unittest_client: httpx.Client
    ):
        monkeypatch.setattr("secrets_env.providers.vault.get_mount", lambda c, p: None)
        assert read_secret(unittest_client, "secrets/test") is None

    @pytest.mark.usefixtures("_set_mount_kv2")
    def test_connection_error(
        self,
        respx_mock: respx.MockRouter,
        unittest_client: httpx.Client,
        caplog: pytest.LogCaptureFixture,
    ):
        respx_mock.get("https://example.com/v1/secrets/data/test").mock(
            side_effect=httpx.ProxyError
        )
        assert read_secret(unittest_client, "secrets/test") is None
        assert (
            "Error occurred during query secret secrets/test: proxy error"
            in caplog.text
        )

    @pytest.mark.usefixtures("_set_mount_kv2")
    def test_http_exception(
        self, respx_mock: respx.MockRouter, unittest_client: httpx.Client
    ):
        respx_mock.get("https://example.com/v1/secrets/data/test").mock(
            side_effect=httpx.DecodingError
        )
        with pytest.raises(httpx.DecodingError):
            read_secret(unittest_client, "secrets/test")

    @pytest.mark.usefixtures("_set_mount_kv2")
    def test_bad_request(
        self,
        respx_mock: respx.MockRouter,
        unittest_client: httpx.Client,
        caplog: pytest.LogCaptureFixture,
    ):
        respx_mock.get("https://example.com/v1/secrets/data/test").mock(
            httpx.Response(499)
        )
        assert read_secret(unittest_client, "secrets/test") is None
        assert "Error occurred during query secret secrets/test" in caplog.text


class TestGetMount:
    @pytest.fixture()
    def route(self, respx_mock: respx.MockRouter):
        return respx_mock.get(
            "https://example.com/v1/sys/internal/ui/mounts/secrets/test"
        )

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
        assert get_mount(unittest_client, "secrets/test") == MountMetadata(
            path="secrets/", version=2
        )

    def test_success_kv2_integration(self, intl_client: httpx.Client):
        assert get_mount(intl_client, "kv2/test") == MountMetadata(
            path="kv2/", version=2
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
        assert get_mount(unittest_client, "secrets/test") == MountMetadata(
            path="secrets/", version=1
        )

    def test_success_kv1_integration(self, intl_client: httpx.Client):
        assert get_mount(intl_client, "kv1/test") == MountMetadata(
            path="kv1/", version=1
        )

    def test_success_legacy(self, route: respx.Route, unittest_client: httpx.Client):
        route.mock(httpx.Response(404))
        assert get_mount(unittest_client, "secrets/test") == MountMetadata(
            path="", version=1
        )

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

        with pytest.raises(ValidationError):
            get_mount(unittest_client, "secrets/test")

    def test_bad_request(
        self,
        route: respx.Route,
        unittest_client: httpx.Client,
        caplog: pytest.LogCaptureFixture,
    ):
        route.mock(httpx.Response(400))
        assert get_mount(unittest_client, "secrets/test") is None
        assert "Error occurred during checking metadata for secrets/test" in caplog.text

    def test_connection_error(
        self,
        route: respx.Route,
        unittest_client: httpx.Client,
        caplog: pytest.LogCaptureFixture,
    ):
        route.mock(side_effect=httpx.ConnectError)
        assert get_mount(unittest_client, "secrets/test") is None
        assert (
            "Error occurred during checking metadata for secrets/test: connection error"
            in caplog.text
        )

    def test_http_exception(self, route: respx.Route, unittest_client: httpx.Client):
        route.mock(side_effect=httpx.DecodingError)
        with pytest.raises(httpx.DecodingError):
            get_mount(unittest_client, "secrets/test")
