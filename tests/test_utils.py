import logging
import os
import sys
import warnings
from pathlib import Path
from unittest.mock import Mock, patch

import click
import httpx
import keyring.errors
import pytest
import shellingham
from pydantic_core import Url

import secrets_env.utils as t


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
    key = t.create_keyring_login_key(
        Url("http://Example.com:8080/foo"), "User@Example.com"
    )
    assert key == '{"host": "example.com", "type": "login", "user": "user@example.com"}'


def test_lru_dict():
    # basic
    d = t.LruDict(max_size=3)
    d["a"] = 1
    d["b"] = 2
    d["c"] = 3
    assert d == {"a": 1, "b": 2, "c": 3}

    # exceed max_size
    d["d"] = 4
    assert d == {"b": 2, "c": 3, "d": 4}

    # update
    d["b"] = 2
    assert d == {"c": 3, "d": 4, "b": 2}

    assert d.get("c") == 3
    assert d.get("e") is None
    assert d == {"d": 4, "b": 2, "c": 3}

    # delete
    del d["b"]
    assert d == {"d": 4, "c": 3}


class TestSetupCaptureWarnings:
    def test_internal(self, caplog: pytest.LogCaptureFixture):
        t.setup_capture_warnings()

        repo_path = Path(__file__).parent.parent
        mock_path = repo_path / "secrets_env" / "mock" / "mock.py"

        with (
            caplog.at_level(logging.CRITICAL),
            caplog.at_level(logging.WARNING, "secrets_env"),
        ):
            warnings.warn_explicit("test warning", UserWarning, str(mock_path), 1)

        assert "test warning" in caplog.text

    def test_external(self, caplog: pytest.LogCaptureFixture):
        t.setup_capture_warnings()

        with (
            caplog.at_level(logging.CRITICAL),
            caplog.at_level(logging.WARNING, "py.warnings"),
        ):
            # NOTE this test file is not in secrets_env package
            warnings.warn("test warning", UserWarning, stacklevel=1)

        assert "UserWarning: test warning" in caplog.text


class TestDetectShell:
    def test_success(self):
        shell, path = t.detect_shell()
        assert isinstance(shell, str)
        assert isinstance(path, Path)

    @pytest.mark.skipif(
        os.getenv("CI") is None, reason="Expect GitHub Action environment"
    )
    def test_success__ci(self):
        shell, path = t.detect_shell()
        assert shell == "sh"
        assert path == Path("/bin/sh")

    @pytest.mark.skipif(
        os.getenv("SHELL") != "/bin/zsh", reason="This is a hard-coded test for zsh"
    )
    def test_success__local(self):
        """Expect local shell is zsh"""
        shell, path = t.detect_shell()
        assert shell == "zsh"
        assert path == Path("/bin/zsh")

    def test_fallback(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(t, "_detect_shell_via_shellingham", lambda: None)
        shell, path = t.detect_shell()
        assert isinstance(shell, str)
        assert isinstance(path, Path)

    @pytest.mark.skipif(
        os.getenv("CI") is None, reason="Expect GitHub Action environment"
    )
    def test_fallback__ci(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(t, "_detect_shell_via_shellingham", lambda: None)
        shell, path = t.detect_shell()
        assert shell == "sh"
        assert path == Path("/bin/sh")

    def test_shellingham_not_installed(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr("builtins.__import__", Mock(side_effect=ImportError))
        assert t._detect_shell_via_shellingham() is None

    def test_shellingham_error(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(
            "shellingham.detect_shell",
            Mock(side_effect=shellingham.ShellDetectionFailure),
        )
        assert t._detect_shell_via_shellingham() is None
