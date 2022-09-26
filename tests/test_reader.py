from http import HTTPStatus
from pathlib import Path
from unittest.mock import Mock, patch

import hvac
import hvac.adapters
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
class TestReader_UnitTest:
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

    @pytest.fixture()
    def patch_version_check(self):
        with patch.object(
            t, "get_engine_and_version", return_value=("secrets/", 1)
        ) as patcher:
            yield patcher

    @pytest.mark.usefixtures("patch_version_check")
    def test_get_secret_success_kv1(self, request_mock: responses.RequestsMock):
        # success, kv1
        request_mock.get(
            "https://example.com/v1/secrets/test",
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
        assert self.reader.get_secret("secrets/test") == {"test": "mock"}

    def test_get_secret_success_kv2(
        self, request_mock: responses.RequestsMock, patch_version_check: Mock
    ):
        # success, kv2
        request_mock.get(
            "https://example.com/v1/secrets/data/test",
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

        patch_version_check.return_value = ("secrets/", 2)
        assert self.reader.get_secret("secrets/test") == {"test": "mock"}

    def test_get_secret_errors(self, patch_version_check: Mock):
        # input error
        with pytest.raises(TypeError):
            self.reader.get_secret(1234)

        # error occurs in get_engine_and_version
        patch_version_check.return_value = (None, None)
        assert self.reader.get_secret("secrets/test") is None

        # unsupported version
        patch_version_check.return_value = ("secrets/", 99)
        with pytest.raises(UnsupportedError):
            self.reader.get_secret("secrets/test")

    @pytest.mark.usefixtures("patch_version_check")
    def test_get_secret_request_error(
        self, request_mock: responses.RequestsMock, caplog: pytest.LogCaptureFixture
    ):
        # request error
        request_mock.get(
            "https://example.com/v1/secrets/test",
            body=requests.ConnectTimeout("test connection error"),
        )
        assert self.reader.get_secret("secrets/test") is None
        assert (
            "Error occurred during query secret secrets/test: connect timeout"
            in caplog.text
        )

    @pytest.mark.usefixtures("patch_version_check")
    def test_get_secret_not_captured_error(self, request_mock: responses.RequestsMock):
        # this function only catch some error. e.g. http error
        request_mock.get(
            "https://example.com/v1/secrets/test",
            body=requests.HTTPError("test request error"),
        )
        with pytest.raises(requests.RequestException):
            self.reader.get_secret("secrets/test")

    @pytest.mark.usefixtures("patch_version_check")
    def test_get_secret_not_found(
        self, request_mock: responses.RequestsMock, caplog: pytest.LogCaptureFixture
    ):
        request_mock.get(
            "https://example.com/v1/secrets/test", status=HTTPStatus.NOT_FOUND
        )
        assert self.reader.get_secret("secrets/test") is None
        assert "Secret not found: secrets/test" in caplog.text

    @pytest.mark.usefixtures("patch_version_check")
    def test_get_secret_server_error(
        self, request_mock: responses.RequestsMock, caplog: pytest.LogCaptureFixture
    ):
        request_mock.get(
            "https://example.com/v1/secrets/test",
            status=HTTPStatus.INTERNAL_SERVER_ERROR,
            json={"msg": "mock error"},
        )
        assert self.reader.get_secret("secrets/test") is None
        assert (
            'Error during query secret secrets/test: {"msg": "mock error"}'
            in caplog.text
        )


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


class TestGetEngineAndVersion:
    URL = "https://example.com/v1/sys/internal/ui/mounts/secrets/test"

    def run(self):
        adapter = hvac.adapters.JSONAdapter(base_uri="https://example.com/")
        return t.get_engine_and_version(adapter, "secrets/test")

    @pytest.mark.parametrize(
        ("options", "version"),
        [
            ({"version": "1"}, 1),
            ({"version": "2"}, 2),
        ],
    )
    def test_success(
        self, request_mock: responses.RequestsMock, options: dict, version: int
    ):
        request_mock.get(
            self.URL,
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
                    "options": options,
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
        assert self.run() == ("secrets/", version)

    def test_success_legacy(self, request_mock: responses.RequestsMock):
        # legacy vault
        request_mock.get(self.URL, status=HTTPStatus.NOT_FOUND)
        assert self.run() == ("", 1)

    def test_not_ported_version(self, request_mock: responses.RequestsMock):
        request_mock.get(
            self.URL,
            status=HTTPStatus.OK,
            json={
                "data": {"path": "mock/", "type": "kv", "options": {"version": "99"}}
            },
        )
        assert self.run() == (None, None)

    def test_unauthorized(
        self, request_mock: responses.RequestsMock, caplog: pytest.LogCaptureFixture
    ):
        request_mock.get(self.URL, status=HTTPStatus.FORBIDDEN)
        assert self.run() == (None, None)
        assert "The used token has no access to path secrets/test" in caplog.text

    def test_bad_request(
        self, request_mock: responses.RequestsMock, caplog: pytest.LogCaptureFixture
    ):
        request_mock.get(self.URL, status=HTTPStatus.BAD_REQUEST)
        assert self.run() == (None, None)
        assert "Error occurred during checking metadata for secrets/test" in caplog.text

    def test_connection_error(
        self, request_mock: responses.RequestsMock, caplog: pytest.LogCaptureFixture
    ):
        request_mock.get(
            self.URL, body=requests.ConnectTimeout("test connection error")
        )
        assert self.run() == (None, None)
        assert (
            "Error occurred during checking metadata secrets/test: connect timeout"
            in caplog.text
        )

    def test_not_captured_error(self, request_mock: responses.RequestsMock):
        # this function only catch some error. e.g. http error
        request_mock.get(self.URL, body=requests.HTTPError("test request error"))
        with pytest.raises(requests.RequestException):
            self.run()


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
