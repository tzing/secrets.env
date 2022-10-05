import subprocess
from unittest.mock import Mock, patch

import click.testing
import pytest

from secrets_env.__main__ import entrypoint
import secrets_env.__main__
import logging
import time


class TestHandler:
    def setup_method(self):
        self.handler = secrets_env.__main__.Handler(logging.DEBUG)
        self.record = logging.makeLogRecord(
            {
                "name": "test",
                "levelno": logging.INFO,
                "levelname": logging.getLevelName(logging.INFO),
                "msg": "\033[31mtest message\033[0m",
                "created": time.time(),
            }
        )

    @pytest.mark.parametrize(
        ("should_strip_ansi", "stderr"),
        [
            (True, "test message\n"),
            (False, "\033[31mtest message\033[0m\n"),
        ],
    )
    def test_success(
        self, capsys: pytest.CaptureFixture, should_strip_ansi: bool, stderr: str
    ):
        with patch("click.utils.should_strip_ansi", return_value=should_strip_ansi):
            self.handler.emit(self.record)

        captured = capsys.readouterr()
        assert captured.err == stderr

    def test_error(self, capsys: pytest.CaptureFixture):
        record = logging.makeLogRecord(
            {
                "name": "test",
                "levelno": logging.ERROR,
                "levelname": logging.getLevelName(logging.ERROR),
                "msg": "%d",
                "created": time.time(),
                "args": ("not-a-num"),
            }
        )

        self.handler.emit(record)

        captured = capsys.readouterr()
        assert "Message: '%d'" in captured.err
