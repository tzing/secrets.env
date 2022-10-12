import logging
import time
from unittest.mock import patch

import click
import click.testing
import pytest

import secrets_env.cli.output as t


class TestClickHandler:
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
        handler = t.ClickHandler()
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

        handler = t.ClickHandler()
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


class TestSetupLogging:
    @pytest.fixture(autouse=True)
    def _reset_logging(self):
        # reset internal
        logger = logging.getLogger("secrets_env")
        logger.setLevel(logging.NOTSET)
        logger.propagate = True
        for h in list(logger.handlers):
            logger.removeHandler(h)

        # reset global
        logger = logging.getLogger()
        logger.setLevel(logging.NOTSET)
        for h in list(logger.handlers):
            logger.removeHandler(h)

    @click.command()
    @t.add_output_options
    def sample_command():
        for logger in (
            logging.getLogger("secrets_env.test"),
            logging.getLogger("mock.test"),
        ):
            logger.debug("test debug msg")
            logger.info("test info msg")
            logger.warning("test warning msg")

    @pytest.fixture()
    def runner(self):
        return click.testing.CliRunner()

    def test_default(self, runner: click.testing.CliRunner):
        res = runner.invoke(self.sample_command)
        assert res.exit_code == 0
        assert "[secrets_env] test debug msg" not in res.output
        assert "[secrets_env] test info msg" in res.output
        assert "[mock] test info msg" not in res.output
        assert "[mock] test warning msg" in res.output

    def test_quiet(self, runner: click.testing.CliRunner):
        res = runner.invoke(self.sample_command, ["-q"])
        assert res.exit_code == 0
        assert "[secrets_env] test info msg" not in res.output
        assert "[secrets_env] test warning msg" in res.output
        assert "[mock] test info msg" not in res.output
        assert "[mock] test warning msg" in res.output

    def test_verbose(self, runner: click.testing.CliRunner):
        res = runner.invoke(self.sample_command, ["-v"])
        assert res.exit_code == 0
        assert "[secrets_env] test debug msg" in res.output
        assert "[mock] test info msg" not in res.output
        assert "[mock] test warning msg" in res.output

    def test_debug(self, runner: click.testing.CliRunner):
        res = runner.invoke(self.sample_command, ["-vvvv"])
        assert res.exit_code == 0
        assert "[secrets_env] test debug msg" in res.output
        assert "[mock] test debug msg" in res.output

    def test_error(self, runner: click.testing.CliRunner):
        res = runner.invoke(self.sample_command, ["-vq"])
        assert res.exit_code == 1
