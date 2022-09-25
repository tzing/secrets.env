from pathlib import Path
from unittest.mock import Mock, patch

import pytest

import secrets_env.config.parse as t
from secrets_env.auth import TokenAuth
from secrets_env.config.types import SecretPath, TLSConfig


def test_parse_config(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("SECRETS_ENV_TOKEN", "ex@mp1e-t0ken")

    # success
    cfg = t.parse_config(
        {
            "source": {
                "url": "https://example.com/",
                "auth": {
                    "method": "token",
                },
            },
            "secrets": {
                "VAR1": "example#val1",
                "VAR2": {"path": "example", "key": "val2"},
                "3VAR": "example#val3",  # name invalid
            },
        }
    )

    assert cfg.url == "https://example.com/"
    assert cfg.auth == TokenAuth("ex@mp1e-t0ken")
    assert cfg.secret_specs == {
        "VAR1": SecretPath("example", "val1"),
        "VAR2": SecretPath("example", "val2"),
    }

    # fail
    assert t.parse_config({}) is None


@pytest.fixture()
def patch_get_auth():
    with patch.object(t, "get_auth") as m:
        yield m.return_value


def test_parse_section_auth(patch_get_auth: Mock):
    assert t.parse_section_auth("test") is patch_get_auth
    assert t.parse_section_auth({"method": "test"}) is patch_get_auth

    assert t.parse_section_auth({}) is None


class TestParseSectionTLS:
    def test_success(self, monkeypatch: pytest.MonkeyPatch):
        # disable file exist check
        monkeypatch.setattr(t, "ensure_path", lambda _, p: (Path(p), True))

        # test all
        assert t.parse_section_tls(
            {
                "ca_cert": "/data/ca.cert",
                "client_cert": "/data/client.cert",
                "client_key": "/data/client.pub",
            }
        ) == {
            "ca_cert": Path("/data/ca.cert"),
            "client_cert": Path("/data/client.cert"),
            "client_key": Path("/data/client.pub"),
        }

        # test standalone
        assert t.parse_section_tls({"ca_cert": "/data/ca.cert"}) == {
            "ca_cert": Path("/data/ca.cert")
        }
        assert t.parse_section_tls({"client_cert": "/data/client.cert"}) == {
            "client_cert": Path("/data/client.cert")
        }
        assert t.parse_section_tls({"client_key": "/data/client.pub"}) == {
            "client_key": Path("/data/client.pub")
        }

    def test_path_not_exist(self):
        assert t.parse_section_tls({"ca_cert": "/data/ca.cert"}) == {}
        assert t.parse_section_tls({"client_cert": "/data/client.cert"}) == {}
        assert t.parse_section_tls({"client_key": "/data/client.pub"}) == {}


class TestGetURL:
    def setup_method(self):
        self.data = {"url": "https://data.example.com"}

    def test_data(self):
        assert t.get_url(self.data) == ("https://data.example.com", True)

    @pytest.mark.parametrize("var_name", ["SECRETS_ENV_ADDR", "VAULT_ADDR"])
    def test_env(self, monkeypatch: pytest.MonkeyPatch, var_name: str):
        monkeypatch.setenv(var_name, "https://env.example.com")
        assert t.get_url(self.data) == ("https://env.example.com", True)

    def test_no_data(self, caplog: pytest.LogCaptureFixture):
        assert t.get_url({}) == (None, False)
        assert "Missing required config '<mark>url</mark>'." in caplog.text

    def test_type_error(self):
        assert t.get_url({"url": object()}) == (None, False)


class TestGetAuthMethod:
    def setup_method(self):
        self.data = {"method": "test"}

    def test_data(self):
        assert t.get_auth_method(self.data) == ("test", True)

    def test_env(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("SECRETS_ENV_METHOD", "env-test")
        assert t.get_auth_method(self.data) == ("env-test", True)

    def test_no_data(self, caplog: pytest.LogCaptureFixture):
        assert t.get_auth_method({}) == (None, False)
        assert "Missing required config '<mark>auth method</mark>'." in caplog.text

    def test_type_error(self):
        assert t.get_auth_method({"method": object()}) == (None, False)


def test_parse_section_secrets():
    assert t.parse_section_secrets(
        {
            "var1": "foo#bar",  # valid
            "VAR2": "foo#",  # path invalid
            "3var": "foo#bar",  # name invalid
            "VAR4": "foo#bar",  # valid
        }
    ) == {
        "var1": SecretPath("foo", "bar"),
        "VAR4": SecretPath("foo", "bar"),
    }


class TestParsePath:
    def test_str(self, caplog: pytest.LogCaptureFixture):
        assert t.parse_path("test", "foo#bar") == SecretPath("foo", "bar")
        assert t.parse_path("test", "foo#b") == SecretPath("foo", "b")
        assert t.parse_path("test", "f#bar") == SecretPath("f", "bar")

        assert t.parse_path("test-fail-1", "") is None
        assert t.parse_path("test-fail-2", "#") is None
        assert t.parse_path("test-fail-3", "foo#") is None
        assert t.parse_path("test-fail-4", "#bar") is None

        assert (
            "Target secret <data>test-fail-4</data> is invalid. "
            "Failed to parse string '<data>#bar</data>'. Skip this variable."
        ) in caplog.text

    def test_dict(self, caplog: pytest.LogCaptureFixture):
        assert t.parse_path("test", {"path": "foo", "key": "bar"}) == SecretPath(
            "foo", "bar"
        )

        assert t.parse_path("test-fail-1", {"path": "foo"}) is None
        assert t.parse_path("test-fail-2", {"key": "bar"}) is None
        assert t.parse_path("test-fail-3", {"path": "foo", "key": 1234}) is None
        assert t.parse_path("test-fail-4", {"path": 1234, "key": "bar"}) is None

        assert (
            "Target secret <data>test-fail-4</data> is invalid. "
            "Missing required key <mark>path</mark> or <mark>key</mark>. "
            "Skip this variable."
        ) in caplog.text


def test_ensure_str(caplog: pytest.LogCaptureFixture):
    assert t.ensure_str("test", "hello") == ("hello", True)

    assert t.ensure_str("not-str", 123) == (None, False)
    assert (
        "Config <mark>not-str</mark> is malformed: "
        "expect <mark>str</mark> type, "
        "got '<data>123</data>' (<mark>int</mark> type)"
    ) in caplog.text


def test_ensure_dict(caplog: pytest.LogCaptureFixture):
    assert t.ensure_dict("test", {"foo": "bar"}) == ({"foo": "bar"}, True)

    assert t.ensure_dict("not-dict", "hello") == ({}, False)
    assert (
        "Config <mark>not-dict</mark> is malformed: "
        "expect <mark>dict</mark> type, "
        "got '<data>hello</data>' (<mark>str</mark> type)"
    ) in caplog.text


def test_ensure_path(caplog: pytest.LogCaptureFixture):
    assert t.ensure_path("test", __file__, True) == (Path(__file__), True)
    assert t.ensure_path("test", Path(__file__), True) == (Path(__file__), True)

    assert t.ensure_path("type-error", 1234) == (None, False)
    assert (
        "Config <mark>type-error</mark> is malformed: "
        "expect <mark>str</mark> type, "
        "got '<data>1234</data>' (<mark>int</mark> type)"
    ) in caplog.text

    assert t.ensure_path("path-error", "/data/not-exist", False) == (
        Path("/data/not-exist"),
        True,
    )

    assert t.ensure_path("path-error", "/data/not-exist", True) == (None, False)
    assert (
        "Config <mark>path-error</mark> is malformed: "
        "path <data>/data/not-exist</data> not exists"
    ) in caplog.text


def test_trimmed_str():
    assert t.trimmed_str("hello") == "hello"
    assert t.trimmed_str(1234) == "1234"
    assert t.trimmed_str({"foo": "bar"}) == "{'foo': 'bar'}"

    assert t.trimmed_str("a very long long long item") == "a very long long ..."
