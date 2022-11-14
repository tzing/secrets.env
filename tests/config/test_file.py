import builtins
import os
from pathlib import Path
from unittest.mock import mock_open

import pytest

import secrets_env.config.file as t


def test_check_installed():
    assert t.check_installed("json") is True
    assert t.check_installed("module-not-exists", "json") is True
    assert t.check_installed("module-not-exists") is False


def test_is_supportted(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
):
    monkeypatch.setitem(t.LANGUAGE_ENABLED, "test-lang", False)
    assert t.is_supportted("json") is True
    assert t.is_supportted("test-lang") is False
    assert t.is_supportted("test-lang") is False
    assert len(caplog.records) == 1
