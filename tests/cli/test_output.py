import logging
import time
from unittest.mock import patch

import pytest

import secrets_env.cli.output as t


class TestHandler:
    def setup_method(self):
        self.handler = t.Handler(logging.DEBUG)
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


class TestFormatter:
    @pytest.fixture(scope="class")
    def formatter(self):
        return t.Formatter()

    @pytest.mark.parametrize(
        ("levelno", "msg"),
        [
            (
                logging.INFO,
                "test with \033[36mmark\033[39m and \033[32mdata\033[39m",
            ),
            (
                logging.WARNING,
                "\033[1m\033[33mtest with \033[36mmark\033[33m and "
                "\033[32mdata\033[33m\033[0m",
            ),
            (
                logging.ERROR,
                "\033[1m\033[31mtest with \033[36mmark\033[31m and "
                "\033[32mdata\033[31m\033[0m",
            ),
            (
                logging.DEBUG,
                "[secrets.env] \033[2m\033[37mtest with \033[36mmark\033[37m and "
                "\033[32mdata\033[37m\033[0m",
            ),
        ],
    )
    def test_success(self, formatter: t.Formatter, levelno: int, msg: str):
        record = logging.makeLogRecord(
            {
                "name": "test",
                "levelno": levelno,
                "levelname": logging.getLevelName(levelno),
                "msg": "test with <mark>mark</mark> and <data>data</data>",
                "created": time.time(),
            }
        )
        assert formatter.format(record) == msg
