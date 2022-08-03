from http import HTTPStatus
from unittest.mock import patch

import hvac
import pytest
import requests
import responses

import vault2env.auth
from vault2env import reader
from vault2env.exception import AuthenticationError, UnsupportedError


@pytest.fixture()
def request_mock():
    with responses.RequestsMock() as rsps:
        yield rsps


class TestReader:
    def setup_method(self):
        # connect to real vault for integration test
        # see .github/workflows/test.yml for test data
        auth = vault2env.auth.TokenAuth("!ntegr@t!0n-test")
        self.reader = reader.KVReader("http://127.0.0.1:8200", auth)

    def test___init__(self):
        with pytest.raises(TypeError):
            reader.KVReader(1234, 1234)
        with pytest.raises(TypeError):
            reader.KVReader("http://example.com", 1234)

    def test_client_success(self):
        """succeed cases; use token, real connection"""
        assert isinstance(self.reader.client, hvac.Client)
        assert isinstance(self.reader.client, hvac.Client)  # from cache

    @patch("hvac.Client")
    def test_client_auth_error(self, client_):
        """failed cases; use token, mocked connection"""
        client = client_.return_value
        client.is_authenticated.return_value = False

        r = reader.KVReader(
            "http://example.com:8200", vault2env.auth.TokenAuth("invalid")
        )
        with pytest.raises(AuthenticationError):
            r.client

    def test_get_engine_and_version(self):
        # success
        assert self.reader.get_engine_and_version("kv1/test") == ("kv1/", 1)
        assert self.reader.get_engine_and_version("kv2/test") == ("kv2/", 2)

        # engine not exists, but things are fine
        assert self.reader.get_engine_and_version("null/test") == (None, None)

        # unknown version
        with responses.RequestsMock() as rsps:
            rsps.get(
                "http://127.0.0.1:8200/v1/sys/internal/ui/mounts/test",
                json={
                    "data": {
                        "path": "mock/",
                        "type": "kv",
                        "options": {"version": "99"},
                    }
                },
            )
            assert self.reader.get_engine_and_version("test") == (None, None)

        # legacy
        with responses.RequestsMock() as rsps:
            rsps.get(
                "http://127.0.0.1:8200/v1/sys/internal/ui/mounts/test",
                status=HTTPStatus.NOT_FOUND,
            )
            assert self.reader.get_engine_and_version("test") == ("", 1)

        # query fail
        with responses.RequestsMock() as rsps:
            rsps.get(
                "http://127.0.0.1:8200/v1/sys/internal/ui/mounts/test",
                status=HTTPStatus.BAD_REQUEST,
                json={"msg": "test error"},
            )
            assert self.reader.get_engine_and_version("test") == (None, None)

        # connection error
        with responses.RequestsMock() as rsps:
            rsps.get(
                "http://127.0.0.1:8200/v1/sys/internal/ui/mounts/test",
                body=requests.ConnectionError("test connection error"),
            )
            assert self.reader.get_engine_and_version("test") == (None, None)

        # request error
        with responses.RequestsMock() as rsps, pytest.raises(requests.RequestException):
            rsps.get(
                "http://127.0.0.1:8200/v1/sys/internal/ui/mounts/test",
                body=requests.HTTPError("test request error"),
            )
            self.reader.get_engine_and_version("test")

    def test_get_secrets(self):
        assert self.reader.get_secrets("kv1/test") == {
            "foo": "hello",
            "bar": {"baz": "world"},
        }
        assert self.reader.get_secrets("kv2/test") == {
            "foo": "hello, world",
            "bar": {
                "baz": "hello, vault",
            },
            "test.key": "value-1",
            "test": {
                "key": "value-2",
                "key.2": "value-3",
            },
            "": {
                "n/a": "value-4",
                '"special key"': "value-5",
            },
        }

    def test_get_secrets_errors(self):
        # input error
        with pytest.raises(TypeError):
            self.reader.get_secrets(1234)

        # internal error
        with patch.object(
            self.reader, "get_engine_and_version", return_value=(None, None)
        ):
            assert self.reader.get_secrets("test") is None

        # unknown version
        with pytest.raises(UnsupportedError), patch.object(
            self.reader, "get_engine_and_version", return_value=("test/", 3)
        ):
            assert self.reader.get_secrets("test") is None

        # secret not found
        assert self.reader.get_secrets("kv1/no-this-secret") is None

    @pytest.mark.parametrize(
        ("kv", "patch_url"),
        [
            (1, "http://127.0.0.1:8200/v1/secret/test"),
            (2, "http://127.0.0.1:8200/v1/secret/data/test"),
        ],
    )
    def test_get_secrets_connection_error(
        self, request_mock: responses.RequestsMock, kv: int, patch_url: str
    ):
        # for client.is_authenticated
        request_mock.get("http://127.0.0.1:8200/v1/auth/token/lookup-self")

        # for get secret
        request_mock.get(
            patch_url,
            body=requests.ConnectionError("test connection error"),
        )

        # test
        with patch.object(
            self.reader, "get_engine_and_version", return_value=("secret/", kv)
        ):
            assert self.reader.get_secrets("secret/test") is None

    @pytest.mark.parametrize(
        ("kv", "patch_url"),
        [
            (1, "http://127.0.0.1:8200/v1/secret/test"),
            (2, "http://127.0.0.1:8200/v1/secret/data/test"),
        ],
    )
    def test_get_secrets_request_error(
        self, request_mock: responses.RequestsMock, kv: int, patch_url: str
    ):
        # for client.is_authenticated
        request_mock.get("http://127.0.0.1:8200/v1/auth/token/lookup-self")

        # for get secret
        request_mock.get(
            patch_url,
            body=requests.HTTPError("test http error"),
        )

        # test
        with patch.object(
            self.reader, "get_engine_and_version", return_value=("secret/", kv)
        ), pytest.raises(requests.RequestException):
            self.reader.get_secrets("secret/test")

    def test_get_secrets_server_error(self):
        with responses.RequestsMock() as rsps, patch.object(
            self.reader, "get_engine_and_version", return_value=("secret/", 2)
        ):
            rsps.get(
                "http://127.0.0.1:8200/v1/auth/token/lookup-self"
            )  # for client.is_authenticated
            rsps.get(
                "http://127.0.0.1:8200/v1/secret/data/test",
                status=HTTPStatus.INTERNAL_SERVER_ERROR,
                json={"msg": "mock error"},
            )  # for get secret
            assert self.reader.get_secrets("secret/test") is None

    def test_get_value(self):
        assert self.reader.get_value("kv1/test", "foo") == "hello"
        assert self.reader.get_value("kv1/test", "bar.baz") == "world"

        assert self.reader.get_value("kv2/test", "'test.key'") == "value-1"
        assert self.reader.get_value("kv2/test", "test.key") == "value-2"
        assert self.reader.get_value("kv2/test", 'test."key.2"') == "value-3"

        assert self.reader.get_value("kv2/test", '""."n/a"') == "value-4"
        assert self.reader.get_value("kv2/test", '.\\"special key\\"') == "value-5"

        assert self.reader.get_value("kv1/test", "no-this-key") is None
        assert self.reader.get_value("no-this-path", "no-this-key") is None

        with pytest.raises(TypeError):
            self.reader.get_value("kv1/test", 1234)

    def test_get_values(self):
        assert self.reader.get_values(
            [
                ("kv1/test", "foo"),
                ("kv1/test", "bar.baz"),
                ("kv2/test", "test.key"),
                ("kv1/test", "no-this-key"),
                ("no-this-secret", "invalid"),
            ]
        ) == {
            ("kv1/test", "foo"): "hello",
            ("kv1/test", "bar.baz"): "world",
            ("kv2/test", "test.key"): "value-2",
            ("kv1/test", "no-this-key"): None,
            ("no-this-secret", "invalid"): None,
        }

        assert self.reader.get_values([]) == {}


def test_split_key():
    assert reader.split_key("aa") == ["aa"]
    assert reader.split_key("aa.bb") == ["aa", "bb"]
    assert reader.split_key("'aa.bb'.cc") == ["aa.bb", "cc"]
    assert reader.split_key('aa."bb.cc"') == ["aa", "bb.cc"]

    assert reader.split_key("aa.bb..cc") == ["aa", "bb", "", "cc"]
    assert reader.split_key("..aa") == ["", "", "aa"]
    assert reader.split_key("aa..") == ["aa", "", ""]

    assert reader.split_key("""aa.'bb."cc"'.dd""") == ["aa", "bb.cc", "dd"]
    assert reader.split_key("""aa.\\'bb."cc"\\'.dd""") == ["aa", "'bb", "cc'", "dd"]


def test_get_value_from_secret():
    data = {
        "foo": {
            "bar": "value-1",
            "baz": {
                "test": "value-2",
            },
        },
        "qax": "value-3",
    }

    assert reader.get_value_from_secret(data, "foo.bar") == "value-1"
    assert reader.get_value_from_secret(data, "foo.baz.test") == "value-2"
    assert reader.get_value_from_secret(data, "qax") == "value-3"

    assert reader.get_value_from_secret(data, "no-this-key") is None

    with pytest.raises(TypeError):
        reader.get_value_from_secret(data, 1234)
