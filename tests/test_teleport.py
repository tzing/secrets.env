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
        mock = Mock(spec=t._RunCommand, return_code=1)
        mock.returncode = 1
        with patch.object(t, "run_teleport", return_value=mock):
            assert t.call_version() is False


class TestCallAppConfig:
    def test_success(self):
        mock = Mock(spec=t._RunCommand, return_code=0)
        mock.stdout = b'{"foo": "bar"}'
        with patch.object(t, "run_teleport", return_value=mock):
            assert t.call_app_config("test") == {"foo": "bar"}

    def test_fail(self):
        mock = Mock(spec=t._RunCommand, return_code=1)
        with patch.object(t, "run_teleport", return_value=mock):
            assert t.call_app_config("test") == {}


class TestRunCommand:
    def test_command(self):
        runner = t._RunCommand(["echo", "hello world"])
        assert runner.command == ("echo", "hello world")

    def test_run(self, caplog: pytest.LogCaptureFixture):
        runner = t._RunCommand(
            [
                "sh",
                "-c",
                """
                echo 'hello world'
                echo 'hello stderr' > /dev/stderr
                exit 36
                """,
            ]
        )

        with caplog.at_level(logging.DEBUG):
            runner.start()
            runner.join()

        assert runner.return_code == 36
        assert runner.stdout == "hello world\n"
        assert runner.stderr == "hello stderr\n"
        assert "< hello world" in caplog.text
        assert "<[stderr] hello stderr" in caplog.text

    def test_iter(self):
        runner = t._RunCommand(
            [
                "sh",
                "-c",
                """
                echo 'item 1'
                echo 'item 2'
                """,
            ]
        )

        runner.start()
        assert list(runner) == ["item 1", "item 2"]
