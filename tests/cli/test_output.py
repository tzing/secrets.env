import logging
import time
from unittest.mock import patch

import pytest

import secrets_env.cli.output as t


class TestSecretsEnvHandler:
    @pytest.mark.parametrize(
        ("name", "level", "verbosity", "output"),
        [
            ("secrets_env", logging.WARNING, t.Verbosity.Quiet, True),
            ("secrets_env.foo", logging.INFO, t.Verbosity.Quiet, False),
            ("secrets_env.foo", logging.INFO, t.Verbosity.Default, True),
            ("secrets_env.foo", logging.DEBUG, t.Verbosity.Default, False),
            ("secrets_env.foo", logging.DEBUG, t.Verbosity.Verbose, True),
            ("test", logging.WARNING, t.Verbosity.Quiet, True),
            ("test", logging.INFO, t.Verbosity.Quiet, False),
            ("test", logging.INFO, t.Verbosity.Default, False),
            ("test", logging.INFO, t.Verbosity.Verbose, False),
            ("test", logging.INFO, t.Verbosity.Debug, True),
        ],
    )
    def test_filter(
        self,
        capsys: pytest.CaptureFixture,
        name: str,
        level: int,
        verbosity: t.Verbosity,
        output: bool,
    ):
        record = logging.makeLogRecord(
            {
                "name": name,
                "levelno": level,
                "levelname": logging.getLevelName(level),
                "msg": "test message",
                "created": time.time(),
            }
        )

        handler = t.SecretsEnvHandler(verbosity)
        handler.handle(record)

        captured = capsys.readouterr()
        if output:
            assert captured.err == "test message\n"
        else:
            assert captured.err == ""

    @pytest.mark.parametrize(
        ("should_strip_ansi", "stderr"),
        [
            (True, "test message\n"),
            (False, "\033[31mtest message\033[0m\n"),
        ],
    )
    def test_emit(
        self, capsys: pytest.CaptureFixture, should_strip_ansi: bool, stderr: str
    ):
        handler = t.SecretsEnvHandler(t.Verbosity.Debug)
        with patch("click.utils.should_strip_ansi", return_value=should_strip_ansi):
            handler.emit(
                logging.makeLogRecord(
                    {
                        "name": "test",
                        "levelno": logging.INFO,
                        "levelname": logging.getLevelName(logging.INFO),
                        "msg": "\033[31mtest message\033[0m",
                        "created": time.time(),
                    }
                )
            )

        captured = capsys.readouterr()
        assert captured.err == stderr

    def test_emit_error(self, capsys: pytest.CaptureFixture):
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

        handler = t.SecretsEnvHandler(t.Verbosity.Debug)
        handler.emit(record)

        captured = capsys.readouterr()
        assert "Message: '%d'" in captured.err


class TestSecretsEnvFormatter:
    @pytest.mark.parametrize(
        ("levelno", "msg"),
        [
            (
                logging.INFO,
                "[test] test with \033[36mmark\033[39m and \033[32mdata\033[39m",
            ),
            (
                logging.WARNING,
                "[test] \033[1m\033[33mtest with \033[36mmark\033[33m and "
                "\033[32mdata\033[33m\033[0m",
            ),
            (
                logging.ERROR,
                "[test] \033[1m\033[31mtest with \033[36mmark\033[31m and "
                "\033[32mdata\033[31m\033[0m",
            ),
            (
                logging.DEBUG,
                "[test] \033[2m\033[37mtest with \033[36mmark\033[37m and "
                "\033[32mdata\033[37m\033[0m",
            ),
        ],
    )
    def test_success_1(self, levelno: int, msg: str):
        record = logging.makeLogRecord(
            {
                "name": "test.foo",
                "levelno": levelno,
                "levelname": logging.getLevelName(levelno),
                "msg": "test with <mark>mark</mark> and <data>data</data>",
                "created": time.time(),
            }
        )

        formatter = t.SecretsEnvFormatter(True)
        assert formatter.format(record) == msg

    def test_success_2(self):
        record = logging.makeLogRecord(
            {
                "name": "test.foo",
                "levelno": logging.INFO,
                "levelname": "INFO",
                "msg": "test with <mark>mark</mark> and <data>data</data>",
                "created": time.time(),
            }
        )

        formatter = t.SecretsEnvFormatter(False)
        assert (
            formatter.format(record)
            == "[test] test with <mark>mark</mark> and <data>data</data>"
        )
