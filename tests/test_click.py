import logging
import time
from unittest.mock import patch

import click
import click.testing
import pytest

import secrets_env.click as t


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


def test_color_formatter():
    record = logging.makeLogRecord(
        {
            "name": "test.foo",
            "levelno": logging.WARNING,
            "levelname": "WARNING",
            "msg": "test with <mark>mark</mark> and <data>data</data>",
            "created": time.time(),
        }
    )

    formatter = t.ColorFormatter()
    assert formatter.format(record) == (
        # style for warning level is applied
        # but style for tags should not take effect
        "[test] "
        "\033[1m\033[33mtest with <mark>mark</mark> and <data>data</data>\033[0m"
    )


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
def test_secrets_env_formatter(levelno: int, msg: str):
    record = logging.makeLogRecord(
        {
            "name": "test.foo",
            "levelno": levelno,
            "levelname": logging.getLevelName(levelno),
            "msg": "test with <mark>mark</mark> and <data>data</data>",
            "created": time.time(),
        }
    )

    formatter = t.SecretsEnvFormatter()
    assert formatter.format(record) == msg


@pytest.mark.usefixtures("_reset_logging")
class TestSetupLogging:
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
            logger.info("<!important>test important info msg")

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
        assert "[secrets_env] test important info msg" in res.output

    def test_quiet(self, runner: click.testing.CliRunner):
        res = runner.invoke(self.sample_command, ["-q"])
        assert res.exit_code == 0

        assert "[secrets_env] test info msg" not in res.output
        assert "[secrets_env] test warning msg" in res.output
        assert "[mock] test info msg" not in res.output
        assert "[mock] test warning msg" in res.output
        assert "[secrets_env] test important info msg" in res.output

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
