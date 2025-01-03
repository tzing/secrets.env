import os
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
from secrets_env.providers.vault.config import VaultUserConfig


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

    def test_ca(self, tmp_path: Path, caplog: pytest.LogCaptureFixture):
        ca_path = tmp_path / "ca.crt"
        ca_path.write_text(EXAMPLE_CA)

        config = VaultUserConfig.model_validate(
            {
                "url": "https://vault.example.com",
                "auth": "null",
                "tls": {
                    "ca_cert": ca_path,
                },
            }
        )

        with caplog.at_level("DEBUG"):
            client = create_http_client(config)

        assert isinstance(client, httpx.Client)
        assert "CA cert is set: " in caplog.text

    def test_client_cert(self, tmp_path: Path, caplog: pytest.LogCaptureFixture):
        cert_path = tmp_path / "client.crt"
        cert_path.write_text(EXAMPLE_CERT + "\n" + EXAMPLE_KEY)

        config = VaultUserConfig.model_validate(
            {
                "url": "https://vault.example.com",
                "auth": "null",
                "tls": {
                    "client_cert": cert_path,
                },
            }
        )

        with caplog.at_level("DEBUG"):
            client = create_http_client(config)

        assert isinstance(client, httpx.Client)
        assert "Client cert is set: " in caplog.text

    def test_client_cert_pair(self, tmp_path: Path, caplog: pytest.LogCaptureFixture):
        cert_path = tmp_path / "client.crt"
        cert_path.write_text(EXAMPLE_CERT)

        key_path = tmp_path / "client.key"
        key_path.write_text(EXAMPLE_KEY)

        config = VaultUserConfig.model_validate(
            {
                "url": "https://vault.example.com",
                "auth": "null",
                "tls": {
                    "client_cert": cert_path,
                    "client_key": key_path,
                },
            }
        )

        with caplog.at_level("DEBUG"):
            client = create_http_client(config)

        assert isinstance(client, httpx.Client)
        assert "Client cert pair is set: " in caplog.text


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


EXAMPLE_CA = """
-----BEGIN CERTIFICATE-----
MIIDbTCCAlWgAwIBAgIUYMsza2nxnl0rLuxDAatRMv7MHwQwDQYJKoZIhvcNAQEL
BQAwRjELMAkGA1UEBhMCVFcxDzANBgNVBAgMBlRhaXBlaTEQMA4GA1UECgwHRXhh
bXBsZTEUMBIGA1UEAwwLZXhhbXBsZS5jb20wHhcNMjQxMjMwMTU1MjQ5WhcNMjUx
MjMwMTU1MjQ5WjBGMQswCQYDVQQGEwJUVzEPMA0GA1UECAwGVGFpcGVpMRAwDgYD
VQQKDAdFeGFtcGxlMRQwEgYDVQQDDAtleGFtcGxlLmNvbTCCASIwDQYJKoZIhvcN
AQEBBQADggEPADCCAQoCggEBAKounDIlEy06X0UNIELgqeNDI/g2UXjz9BCPMn/k
odJiI9bK1vzbrAxTR8CLiSk6+9jFLgF7mBU4nHR0N+hz+5tjkRtyKSzDYVby9K63
F4nEKPghZCPtflBcLkLgI3v/i8JIRfQWAOURe6ulIlTqRUT+fjm4m2QSgruMj8me
N0pDbRxg3c0TlrTNOQ6mn/tf8YStAWJi7pzcWWFgnq5SS83g6YQ7f9FtdlVFYnqX
jcAigoC7VxIXelgVb7ECy7ujPU6FVcPPy5TfuKoari6BqiaXG7GRZLacU2SfWW2B
84V9w6SpY0srrVEd/GteP7cPqpyUaTUAWngHdkz5Yn2jpT0CAwEAAaNTMFEwHQYD
VR0OBBYEFDFFnAgA0894Qt5dfLYNc+kIEbW9MB8GA1UdIwQYMBaAFDFFnAgA0894
Qt5dfLYNc+kIEbW9MA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEB
AIT0tuEE7twMSiobXMnNtkryt4pPsF5VAsOXIgiUqAou4kYQbHh1HFFkQYsl0DyE
xRz3zSqoA+f2DssA6JCf0Bl/vU1JaMYqu+177D7JHMLvdYE1QD938o5ecNzZhuv4
YZXJBy9jVoFQLV/KwQ4JFoT2EojPBAkKDyBX7maMbev8qSvek2GQXynFZdINdnbE
iCeUR4TqNGDoH86S4Q4PXhuhIXjJAJJek49F2+/eG56AtyWOAQ+NjoY6ESoWGUTG
akK03aA3oINey+TmjbE1TumvcxhOFxdCDAcAXF6VUqU4x/95SbNTg7vfQKp6guob
TSLAQILNPnAJ3S74ZKXCsgQ=
-----END CERTIFICATE-----
"""

EXAMPLE_CERT = """
-----BEGIN CERTIFICATE-----
MIIDXDCCAkSgAwIBAgIUE2Y2mm1okum8MoT2L/uy0kBi/fQwDQYJKoZIhvcNAQEL
BQAwRjELMAkGA1UEBhMCVFcxDzANBgNVBAgMBlRhaXBlaTEQMA4GA1UECgwHRXhh
bXBsZTEUMBIGA1UEAwwLZXhhbXBsZS5jb20wHhcNMjQxMjMwMTYwMTQ2WhcNMjUx
MjMwMTYwMTQ2WjBGMQswCQYDVQQGEwJUVzEPMA0GA1UECAwGVGFpcGVpMRAwDgYD
VQQKDAdFeGFtcGxlMRQwEgYDVQQDDAtleGFtcGxlLmNvbTCCASIwDQYJKoZIhvcN
AQEBBQADggEPADCCAQoCggEBALbXs/vjx7gFahk4hk+EmSsTAw2xH2JWHVTSRuzF
nwgxCHmy6NrkTfBlqRlumK/Z/l9IA8uLRDZprvN3qpvjiMUbyAqd5IhQ9yJ39MuA
BIjHqNlCVug8t1Xi23Fvi6FY1G+4c+6/sL2D6sfiVAVHxfb6ugbRnjQ1IfKE0Zot
POkJTTWOUy+c6dk9+vkASNHUriiID/bDFGRqGn84DIdVfVz8VPlsPWrbvv5WSrpk
+5Kxyj3GxwIK/aau1QQ8xAdy2wDGi6GYf4cLM85shf3uCnirMenDU5W/lT5M/WaT
7rV4ShQo88t3UmSB/dglxO1hjdJvZxBVlN4R7/fH3SRJDo8CAwEAAaNCMEAwHQYD
VR0OBBYEFNGu3DwUBs4/4l+vIl8SmbDEM+2nMB8GA1UdIwQYMBaAFDFFnAgA0894
Qt5dfLYNc+kIEbW9MA0GCSqGSIb3DQEBCwUAA4IBAQCpBgGg5n9mCcJNOZ/8PcH/
E2f19TFAs/qlde3NL6Rq5ICsMrHvUE/Jy3nDTj0n8IFv8dSosUWaoouKMQjmmQLQ
/gas8eGhMBva+tT3zTOino4brlph1BnpUg3s0cvvjOOeXICKSHbIlTQh9WfTGuI6
fljM9uyWx+nlH3e6RiSL74yTjFxeLEi95BkOoqBJOykw0ROaSXKlIrRhPs5jTSMY
3OvNjBOn8PyEWzhIIoSHHMUouTAsID5cbreJxZ0A7rowETZnXdMpctgnZiYBLP2V
SQBnXF4HdgvFz7i6o0Y7eiR+epslnzmUC+Tw9+O16pCy1ZkMBZCoIV9OKASGkdYx
-----END CERTIFICATE-----
"""

EXAMPLE_KEY = """
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC217P748e4BWoZ
OIZPhJkrEwMNsR9iVh1U0kbsxZ8IMQh5suja5E3wZakZbpiv2f5fSAPLi0Q2aa7z
d6qb44jFG8gKneSIUPcid/TLgASIx6jZQlboPLdV4ttxb4uhWNRvuHPuv7C9g+rH
4lQFR8X2+roG0Z40NSHyhNGaLTzpCU01jlMvnOnZPfr5AEjR1K4oiA/2wxRkahp/
OAyHVX1c/FT5bD1q277+Vkq6ZPuSsco9xscCCv2mrtUEPMQHctsAxouhmH+HCzPO
bIX97gp4qzHpw1OVv5U+TP1mk+61eEoUKPPLd1Jkgf3YJcTtYY3Sb2cQVZTeEe/3
x90kSQ6PAgMBAAECggEAAlxtQoDuNT0t/ke22vPm4xqsWySg4kl4uLafhp2+c9Ag
gGQHiy5I/HmLl4OltBnYCVSbyijNgGonD86QZO4pMM2EM/EdrqNkkgXDhoczDuap
IMrb5lNEnFpdayzaEZFAlXVnzPPWZiXfjReNtWv4H0pkHDzDtkb8QYO74ynXYgOg
iRrC+3G+rJj14eW5+9FQ3zJJ6cQq90q0gp7Fp39IzV2ZcL7fYQArHe3/hArQ9ODg
X466wUfgX3zD2idPbz8I0ujQYOzSGNdgIcXuEQbNKdOppoOtSymXaWIiDHXUj5hQ
D7EcS7cfSxv9+C1s6/62w4MrZ0VsO09eWEhZ3fw4yQKBgQDbd+PemD3DvWADEqRy
Jmya14BT6if0fl1dQQCrAzPAkrwRUd1wvjsDl8YCQwwqciLPCSpEHfydwM7y23hu
9bwDz2i3FvcdNZI2AhczEI5KngyYlm35Re/E1abiQvrdW1SfSetPAQesumNkjEsp
ZhskwidfhjUbszXFAWayHkUv2QKBgQDVRxioQbZEVuXoHKiKsd6/9PiK8YHyXhuW
isgHI1mXwWhNs2UmsKFNLTAjR6t3oPhpKver19DE4/elC4bDcr4QB5RlHXweiufd
vQ4ZjJjH2SjdmoYYxJyrQlol++w/yrU9lfCtf5M41Bj+2g+u6Z0zTRqyUcNRoyy8
zmguXe6YpwKBgQCJVGcJVbhocGrQ4Wx3ZWXWKn1JhR9FVYE0pkU1vYY3vVnjeJeZ
QeAJqoIjzjKhqNPxO2nwP9dgG1MkEoM0452nwLRkxQESjQAVvY8oy/ZN6MI3BQKB
1epn/80yjfkOZGT6W7XbtOhJhERHmaY6nILlqHwcwQ0gbS57PRo24MwoWQKBgD4Y
chRi9XdWOZ/n4CZpfSo0X7zMbgIr5iphg7WYVDh75ithRN0L5hq7Ql2zOzgcVNcB
3JRaxHzexrZ18amsGaw/GLSL7hxSYwnLRnSn27+r+Vrz54EElXzDV83hWDqGgVhJ
9IX/M9UC47gnsxNBDzTliRVL+usk8ByUl/6P+KzXAoGBAM+g1Y5FYw7EYMgeKwnG
535rMAL+cTUPOP1Rxff+ggsZZOy4JG8KKNnjWgJmHYvSnGpDZ+ZOd1sn2QLdXDRG
YKWFJktyiou8qUWjOtrhmJXtkOrhNs3hyfCZLzJr2qWi6/0p4QucPCtDXCbVwouk
fTuBgGWvfroEfnT/OCf98zHH
-----END PRIVATE KEY-----
"""
