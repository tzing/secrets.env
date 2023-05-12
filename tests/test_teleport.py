import logging
import re
import shutil
import subprocess
from unittest.mock import Mock, patch

import pytest

import secrets_env.teleport as t

no_teleport_cli = shutil.which("tsh") is None


class TestCallVersion:
    @pytest.mark.skipif(no_teleport_cli, reason="Teleport CLI not installed")
    def test_success(self, caplog: pytest.LogCaptureFixture):
        with caplog.at_level(logging.DEBUG):
            assert t.call_version() is True
        assert re.search(r"< Teleport v\d+\.\d+\.\d+", caplog.text)

    def test_fail(self):
        mock = Mock(spec=subprocess.CompletedProcess)
        mock.returncode = 1
        with patch("subprocess.run", return_value=mock):
            assert t.call_version() is False


class TestCallAppConfig:
    def test_success(self):
        mock = Mock(spec=subprocess.CompletedProcess)
        mock.returncode = 0
        mock.stdout = b'{"foo": "bar"}'
        with patch("subprocess.run", return_value=mock):
            assert t.call_app_config("test") == {"foo": "bar"}

    def test_fail(self):
        mock = Mock(spec=subprocess.CompletedProcess)
        mock.returncode = 1
        with patch("subprocess.run", return_value=mock):
            assert t.call_app_config("test") == {}
