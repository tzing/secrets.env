import os
import ssl
import uuid
from pathlib import Path
from unittest.mock import Mock, PropertyMock

import httpx
import pytest
from pydantic import HttpUrl, ValidationError

from secrets_env.exceptions import AuthenticationError, NoValue
from secrets_env.provider import Request
from secrets_env.providers.teleport.config import (
    TeleportConnectionParameter,
    TeleportUserConfig,
)
from secrets_env.providers.vault import (
    VaultKvProvider,
    VaultPath,
    _split_field_str,
    create_http_client,
    get_token,
    get_token_from_helper,
    save_token_to_helper,
)
from secrets_env.providers.vault.auth.base import Auth, NoAuth
from secrets_env.providers.vault.config import TlsConfig, VaultUserConfig


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
        with pytest.raises(ValidationError, match="Expected 'path#field'"):
            VaultPath.model_validate({"value": "foobar"})

        # too many path/field separator
        with pytest.raises(ValidationError, match="Expected 'path#field'"):
            VaultPath.model_validate({"value": "foo#bar#baz"})

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
    @pytest.fixture
    def random_token(self) -> str:
        return uuid.uuid4().hex

    def test_client(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, random_token: str
    ):
        helper = tmp_path / ".vault-token"
        monkeypatch.setattr(
            "secrets_env.providers.vault.get_token_helper_path",
            lambda: helper,
        )
        monkeypatch.setattr(
            "secrets_env.providers.vault.create_http_client",
            lambda _: Mock(httpx.Client, headers={}),
        )
        monkeypatch.setattr(
            "secrets_env.providers.vault.get_token", lambda c, a: random_token
        )

        provider = VaultKvProvider(url="https://vault.example.com", auth="null")
        assert isinstance(provider.client, httpx.Client)
        assert provider.client.headers["X-Vault-Token"] == random_token
        assert helper.read_text() == random_token

    def test_client__use_helper(
        self, monkeypatch: pytest.MonkeyPatch, random_token: str
    ):
        monkeypatch.setattr(
            "secrets_env.providers.vault.create_http_client",
            lambda _: Mock(httpx.Client, headers={}),
        )
        monkeypatch.setattr(
            "secrets_env.providers.vault.get_token_from_helper", lambda _: random_token
        )

        provider = VaultKvProvider(url="https://vault.example.com", auth="null")
        assert isinstance(provider.client, httpx.Client)
        assert provider.client.headers["X-Vault-Token"] == random_token

    def test_client__with_teleport(
        self, monkeypatch: pytest.MonkeyPatch, random_token: str
    ):
        def mock_create_http_client(config: VaultUserConfig):
            assert config.url == HttpUrl("https://vault.teleport.example.com/")
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
        monkeypatch.setattr(
            "secrets_env.providers.vault.get_token_from_helper", lambda _: None
        )
        monkeypatch.setattr(
            "secrets_env.providers.vault.get_token", lambda c, a: random_token
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
        assert provider.client.headers["X-Vault-Token"] == random_token

    @pytest.fixture
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

    @pytest.fixture
    def mock_httpx_client(self, monkeypatch: pytest.MonkeyPatch):
        client = Mock(httpx.Client)
        monkeypatch.setattr("httpx.Client", client)
        return client

    def test_ca(self, monkeypatch: pytest.MonkeyPatch, mock_httpx_client: Mock):
        mock_ssl_ctx = Mock(ssl.SSLContext)
        monkeypatch.setattr("ssl.SSLContext", Mock(return_value=mock_ssl_ctx))

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
        assert kwargs["verify"] is mock_ssl_ctx

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


class TestSaveTokenToHelper:
    def test(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
        helper = tmp_path / ".vault-token"
        monkeypatch.setattr(
            "secrets_env.providers.vault.get_token_helper_path",
            lambda: helper,
        )
        save_token_to_helper("t0ken")
        assert helper.read_text() == "t0ken"

    def test_root(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr("os.getuid", lambda: 0)

        mock_open = Mock()
        monkeypatch.setattr("io.open", mock_open)

        save_token_to_helper("t0ken")

        mock_open.assert_not_called()

    def test_exception(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr("io.open", Mock(side_effect=OSError))
        save_token_to_helper("t0ken")  # no exception


class TestGetTokenFromHelper:
    def test_success(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
        helper = tmp_path / "helper"
        helper.write_text("t0ken")

        monkeypatch.setattr(
            "secrets_env.providers.vault.get_token_helper_path",
            lambda: helper,
        )
        monkeypatch.setattr(
            "secrets_env.providers.vault.is_authenticated",
            lambda c, t: True,
        )

        assert get_token_from_helper(Mock(httpx.Client)) == "t0ken"

    def test_not_found(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr("pathlib.Path.is_file", lambda _: False)
        assert get_token_from_helper(Mock(httpx.Client)) is None

    def test_expired(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
        helper = tmp_path / "helper"
        helper.write_text("t0ken")

        monkeypatch.setattr(
            "secrets_env.providers.vault.get_token_helper_path",
            lambda: helper,
        )
        monkeypatch.setattr(
            "secrets_env.providers.vault.is_authenticated",
            lambda c, t: False,
        )

        assert get_token_from_helper(Mock(httpx.Client)) is None
