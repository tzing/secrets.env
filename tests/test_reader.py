from http import HTTPStatus
from pathlib import Path
from unittest.mock import Mock, patch

import hvac
import pytest
import requests
import requests.exceptions
import responses

import secrets_env.auth
import secrets_env.reader as t
from secrets_env import reader
from secrets_env.exception import AuthenticationError, UnsupportedError


@pytest.fixture()
def request_mock():
    with responses.RequestsMock() as rsps:
        yield rsps


@pytest.fixture()
def _set_authenticated():
    with patch("hvac.Client.is_authenticated", return_value=True):
        yield


@pytest.mark.usefixtures("_set_authenticated")
class TestReader_1:
    # unit tests for Reader class

    def setup_method(self):
        self.auth = Mock(spec=secrets_env.auth.Auth)
        self.auth.method.return_value = "mocked"

        self.reader = t.KVReader(
            url="https://example.com/",
            auth=self.auth,
            tls={
                "ca_cert": Path("/path/ca.cert"),
                "client_cert": Path("/path/client.cert"),
                "client_key": Path("/path/client.key"),
            },
        )

    def test___init__type_error(self):
        with pytest.raises(TypeError):
            reader.KVReader(1234, self.auth)
        with pytest.raises(TypeError):
            reader.KVReader("https://example.com", 1234)
        with pytest.raises(TypeError):
            reader.KVReader("https://example.com", self.auth, 1234)

    def test_client(self):
        assert isinstance(self.reader.client, hvac.Client)
        assert isinstance(self.reader.client, hvac.Client)  # from cache

    def test_get_engine_and_version_1(self, request_mock: responses.RequestsMock):
        # standard response
        request_mock.get(
            "https://example.com/v1/sys/internal/ui/mounts/secrets/test",
            status=HTTPStatus.OK,
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
        assert self.reader.get_engine_and_version("secrets/test") == ("secrets/", 2)

    def test_get_engine_and_version_2(self, request_mock: responses.RequestsMock):
        # legacy vault
        request_mock.get(
            "https://example.com/v1/sys/internal/ui/mounts/secrets/test",
            status=HTTPStatus.NOT_FOUND,
        )
        assert self.reader.get_engine_and_version("secrets/test") == ("", 1)

    @pytest.mark.parametrize(
        ("status_code", "body"),
        [
            # not a ported version
            (
                HTTPStatus.OK,
                {"data": {"path": "mock/", "type": "kv", "options": {"version": "99"}}},
            ),
            # query fail
            (HTTPStatus.BAD_REQUEST, {"msg": "test error"}),
        ],
    )
    def test_get_engine_and_version_3(
        self,
        request_mock: responses.RequestsMock,
        status_code: int,
        body: dict,
    ):
        # internal errors
        request_mock.get(
            "https://example.com/v1/sys/internal/ui/mounts/test",
            status=status_code,
            json=body,
        )
        assert self.reader.get_engine_and_version("test") == (None, None)

    def test_get_engine_and_version_4(self, request_mock: responses.RequestsMock):
        # connection error
        request_mock.get(
            "https://example.com/v1/sys/internal/ui/mounts/test",
            body=requests.ConnectTimeout("test connection error"),
        )
        assert self.reader.get_engine_and_version("test") == (None, None)

    def test_get_engine_and_version_5(self, request_mock: responses.RequestsMock):
        # this function only catch some error. e.g. connection error
        request_mock.get(
            "https://example.com/v1/sys/internal/ui/mounts/test",
            body=requests.HTTPError("test request error"),
        )
        with pytest.raises(requests.RequestException):
            self.reader.get_engine_and_version("test")


class _Reader_FunctionalTest:
    def setup_method(self):
        # connect to real vault for integration test
        # see .github/workflows/test.yml for test data
        auth = secrets_env.auth.TokenAuth("!ntegr@t!0n-test")
        self.reader = reader.KVReader("http://127.0.0.1:8200", auth)

    def test_client(self):
        assert isinstance(self.reader.client, hvac.Client)

    @patch("hvac.Client")
    def test_client_auth_error(self, client_: Mock):
        """failed cases; use token, mocked connection"""
        client = client_.return_value
        client.is_authenticated.return_value = False

        r = reader.KVReader(
            "http://example.com:8200", secrets_env.auth.TokenAuth("invalid")
        )
        with pytest.raises(AuthenticationError):
            r.client

    def test_get_engine_and_version(self):
        # success
        assert self.reader.get_engine_and_version("kv1/test") == ("kv1/", 1)
        assert self.reader.get_engine_and_version("kv2/test") == ("kv2/", 2)

        # engine not exists, but things are fine
        assert self.reader.get_engine_and_version("null/test") == (None, None)

        # NOTE test for errors are in `TestReaderGetEngineAndVersion` class below

    def test_get_secret(self):
        # success
        assert self.reader.get_secret("kv1/test") == {
            "foo": "hello",
            "bar": {"baz": "world"},
        }
        assert self.reader.get_secret("kv2/test") == {
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

        # not found
        assert self.reader.get_secret("kv1/no-this-secret") is None

        # NOTE test for errors are in `TestReaderGetSecret` class below

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


class TestReaderGetSecret:
    def setup_method(self):
        auth = Mock(spec=secrets_env.auth.Auth)
        auth.method.return_value = "mocked"

        self.reader = reader.KVReader("https://example.com", auth)

    def test_input_error(self):
        with pytest.raises(TypeError):
            self.reader.get_secret(1234)

    def test_internal_error(self):
        with patch.object(
            self.reader, "get_engine_and_version", return_value=(None, None)
        ):
            assert self.reader.get_secret("test") is None

    def test_unimplemented_version(self):
        with pytest.raises(UnsupportedError), patch.object(
            self.reader, "get_engine_and_version", return_value=("test/", 3)
        ):
            assert self.reader.get_secret("test") is None

    @pytest.mark.parametrize(
        ("kv", "patch_url"),
        [
            (1, "https://example.com/v1/secret/test"),
            (2, "https://example.com/v1/secret/data/test"),
        ],
    )
    @pytest.mark.usefixtures("_set_authenticated")
    def test_connection_error(
        self, request_mock: responses.RequestsMock, kv: int, patch_url: str
    ):
        request_mock.get(
            patch_url,
            body=requests.ConnectTimeout("test connection error"),
        )

        # test
        with patch.object(
            self.reader, "get_engine_and_version", return_value=("secret/", kv)
        ):
            assert self.reader.get_secret("secret/test") is None

    @pytest.mark.parametrize(
        ("kv", "patch_url"),
        [
            (1, "https://example.com/v1/secret/test"),
            (2, "https://example.com/v1/secret/data/test"),
        ],
    )
    @pytest.mark.usefixtures("_set_authenticated")
    def test_request_error(
        self, request_mock: responses.RequestsMock, kv: int, patch_url: str
    ):
        request_mock.get(
            patch_url,
            body=requests.HTTPError("test http error"),
        )

        # test
        with patch.object(
            self.reader, "get_engine_and_version", return_value=("secret/", kv)
        ), pytest.raises(requests.RequestException):
            self.reader.get_secret("secret/test")

    @pytest.mark.usefixtures("_set_authenticated")
    def test_server_side_error(self, request_mock: responses.RequestsMock):
        with patch.object(
            self.reader, "get_engine_and_version", return_value=("secret/", 2)
        ):
            request_mock.get(
                "https://example.com/v1/secret/data/test",
                status=HTTPStatus.INTERNAL_SERVER_ERROR,
                json={"msg": "mock error"},
            )
            assert self.reader.get_secret("secret/test") is None


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

    assert reader._get_value_from_secret(data, "foo.bar") == "value-1"
    assert reader._get_value_from_secret(data, "foo.baz.test") == "value-2"
    assert reader._get_value_from_secret(data, "qax") == "value-3"

    assert reader._get_value_from_secret(data, "no-this-key") is None

    with pytest.raises(TypeError):
        reader._get_value_from_secret(data, 1234)


def test_reason_request_error():
    # proxy
    error = requests.exceptions.ProxyError("mocked")
    assert reader._reason_request_error(error) == "proxy error"

    # ssl
    error = requests.exceptions.SSLError("mocked")
    assert reader._reason_request_error(error) == "SSL error"

    # timeout
    error = requests.exceptions.ReadTimeout("mocked")
    assert reader._reason_request_error(error) == "connect timeout"
    error = requests.exceptions.ConnectTimeout("mocked")
    assert reader._reason_request_error(error) == "connect timeout"

    # os error
    error = OSError("mocked")
    error = requests.ConnectionError(error)
    assert reader._reason_request_error(error) == "OS error"

    # not captured
    error = requests.ConnectionError("mocked")
    assert reader._reason_request_error(error) is None
