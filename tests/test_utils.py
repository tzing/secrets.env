import logging
import sys
from pathlib import Path
from unittest.mock import Mock, patch

import click
import httpx
import keyring.errors
import pytest

import secrets_env.utils as t


class TestEnsureType:
    def test_success(self):
        assert t.ensure_type("test", 1234, "mock", int, True, 0) == (1234, True)
        assert t.ensure_type("test", "1234", "mock", int, True, 0) == (1234, True)

    def test_no_cast(self, caplog: pytest.LogCaptureFixture):
        assert t.ensure_type("test", "1234", "mock", int, False, 0) == (0, False)
        assert (
            "Expect <mark>mock</mark> type for config <mark>test</mark>, "
            "got <data>1234</data> (<mark>str</mark> type)"
        ) in caplog.text

    def test_cast_fail(self, caplog: pytest.LogCaptureFixture):
        assert t.ensure_type("test", "not a number", "mock", int, True, 0) == (0, False)
        assert (
            "Expect <mark>mock</mark> type for config <mark>test</mark>, "
            "got <data>not a number</data> (<mark>str</mark> type)"
        ) in caplog.text


def test_ensure_str():
    assert t.ensure_str("test", "hello") == ("hello", True)
    assert t.ensure_str("test", "") == ("", True)

    assert t.ensure_str("test", 1234) == (None, False)
    assert t.ensure_str("test", {"foo": "bar"}) == (None, False)


def test_ensure_dict():
    assert t.ensure_dict("test", {"foo": "bar"}) == ({"foo": "bar"}, True)
    assert t.ensure_dict("not-dict", "hello") == ({}, False)


def test_ensure_path(caplog: pytest.LogCaptureFixture):
    # pass
    path = Path("/data/file")
    assert t.ensure_path("test", path, False) == (Path("/data/file"), True)

    # casted
    assert t.ensure_path("test", "/data/file", False) == (Path("/data/file"), True)

    # can't cast
    assert t.ensure_path("test", 1234, False) == (None, False)

    # not exist
    assert t.ensure_path("test", "/data/file", True) == (None, False)
    assert (
        "Expect valid path for config <mark>test</mark>: "
        "file <data>/data/file</data> not exists"
    ) in caplog.text


def test_trimmed_str():
    assert t.trimmed_str("hello") == "hello"
    assert t.trimmed_str(1234) == "1234"
    assert t.trimmed_str({"foo": "bar"}) == "{'foo': 'bar'}"

    assert t.trimmed_str("a very long long long item") == "a very long long ..."


def test_get_httpx_error_reason():
    assert t.get_httpx_error_reason(Mock(spec=httpx.ProxyError)) == "proxy error"
    assert (
        t.get_httpx_error_reason(Mock(spec=httpx.TransportError)) == "connection error"
    )


class TestLogHttpxResponse:
    @pytest.fixture(autouse=True)
    def _use_debug(self, caplog: pytest.LogCaptureFixture):
        caplog.set_level(logging.DEBUG)

    def setup_method(self):
        self.request = httpx.Request("GET", "https://example.com/")
        self.logger = logging.getLogger(__name__)

    def test_plain(self, caplog: pytest.LogCaptureFixture):
        resp = httpx.Response(200, request=self.request, content=b"sample response")

        t.log_httpx_response(self.logger, resp)

        assert "URL= https://example.com/;" in caplog.text
        assert "Status= 200 (OK);" in caplog.text
        assert "Raw response= sample response" in caplog.text

    def test_json(self, caplog: pytest.LogCaptureFixture):
        resp = httpx.Response(403, request=self.request, json={"foo": "bar"})

        t.log_httpx_response(self.logger, resp)

        assert "URL= https://example.com/;" in caplog.text
        assert "Status= 403 (Forbidden);" in caplog.text
        assert 'Raw response= {"foo": "bar"}' in caplog.text

    def test_error(self, caplog: pytest.LogCaptureFixture):
        resp = httpx.Response(
            999, request=self.request, content=b"\xa0 undecodable bytes"
        )

        t.log_httpx_response(self.logger, resp)

        assert "URL= https://example.com/;" in caplog.text
        assert "Status= 999 (Unknown);" in caplog.text
        assert "Raw response= \ufffd undecodable bytes" in caplog.text


def test_get_env_var(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("SECRETS_ENV_ITEM_1", "value-1")
    monkeypatch.setenv("SECRETS_ENV_ITEM_2", "value-2")
    monkeypatch.setenv("secrets_env_item_3", "value-3")

    assert t.get_env_var("SECRETS_ENV_ITEM_1") == "value-1"
    assert t.get_env_var("SECRETS_ENV_ITEM_3") == "value-3"
    assert t.get_env_var("SECRETS_ENV_ITEM_1", "SECRETS_ENV_ITEM_2") == "value-1"
    assert t.get_env_var("NO_THIS_ENV", "SECRETS_ENV_ITEM_2") == "value-2"
    assert t.get_env_var("NO_THIS_ENV_1", "NO_THIS_ENV_2") is None


class TestPrompt:
    def test_disable(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("SECRETS_ENV_NO_PROMPT", "True")
        assert t.prompt("test") is None

    def test_success(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("SECRETS_ENV_NO_PROMPT", "Foo")
        with patch("click.prompt", return_value="buzz"):
            assert t.prompt("test") == "buzz"

    def test_abort(self):
        with patch("click.prompt", side_effect=click.Abort("mock abort")):
            assert t.prompt("test") is None


class TestKeyring:
    def test_success(self):
        with patch("keyring.get_password", return_value="bar"):
            assert t.read_keyring("test") == "bar"

    def test_error(self):
        with patch("keyring.get_password", side_effect=keyring.errors.NoKeyringError()):
            assert t.read_keyring("test") is None

    def test_disable(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("SECRETS_ENV_NO_KEYRING", "True")
        assert t.read_keyring("test") is None

    def test_not_install(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setitem(sys.modules, "keyring", None)
        assert t.read_keyring("test") is None


def test_create_keyring_login_key():
    assert (
        t.create_keyring_login_key("http://Example.com/foo", "User@Example.com")
        == '{"host": "example.com", "type": "login", "user": "user@example.com"}'
    )


def test_create_keyring_token_key():
    assert (
        t.create_keyring_token_key("https://Example.com/foo")
        == '{"host": "example.com", "type": "token"}'
    )


def test_extract_http_host():
    assert t.extract_http_host("EXAMPLE.COM:80") == "example.com"
    assert t.extract_http_host("HTTP://example.com:80") == "example.com"
    assert t.extract_http_host("127.0.0.1") == "127.0.0.1"
    assert t.extract_http_host("[::1]:80") == "::1"

    with pytest.raises(ValueError, match="Invalid scheme: ftp"):
        t.extract_http_host("ftp://example.com")
