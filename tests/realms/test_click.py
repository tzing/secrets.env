import logging
import time

import pytest

from secrets_env.realms.click.logging import (
    ClickHandler,
    ColorFormatter,
    LevelFilter,
    SecretsEnvFilter,
    SecretsEnvFormatter,
)


def test_color_formatter():
    record = logging.makeLogRecord(
        {
            "name": "test.foo",
            "levelno": logging.WARNING,
            "msg": "test with <mark>mark</mark> and <data>data</data>",
        }
    )

    formatter = ColorFormatter()

    # style for warning level is applied
    # but style for tags should not take effect
    assert formatter.format(record) == (
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
            "msg": "test with <mark>mark</mark> and <data>data</data>",
        }
    )

    formatter = SecretsEnvFormatter()
    assert formatter.format(record) == msg


class TestLevelFilter:
    def test(self):
        f = LevelFilter(logging.WARNING)
        assert not f.filter(logging.makeLogRecord({"levelno": logging.INFO}))
        assert f.filter(logging.makeLogRecord({"levelno": logging.WARNING}))
        assert f.filter(logging.makeLogRecord({"levelno": logging.ERROR}))


class TestSecretsEnvFilter:
    def test(self):
        f = SecretsEnvFilter(logging.WARNING)
        assert not f.filter(logging.makeLogRecord({"levelno": logging.INFO}))
        assert f.filter(logging.makeLogRecord({"levelno": logging.WARNING}))
        assert f.filter(logging.makeLogRecord({"levelno": logging.ERROR}))
        assert f.filter(
            logging.makeLogRecord(
                {
                    "levelno": logging.INFO,
                    "msg": "<!important>test important info message",
                }
            )
        )


class TestClickHandler:
    def test_emit__success(self, capsys: pytest.CaptureFixture):
        handler = ClickHandler()
        handler.handle(logging.makeLogRecord({"msg": "test message"}))
        captured = capsys.readouterr()
        assert captured.err == "test message\n"

    def test_emit__error(self, capsys: pytest.CaptureFixture):
        handler = ClickHandler()
        handler.handle(
            logging.makeLogRecord(
                {
                    "msg": "%d",
                    "args": ("not-a-num"),
                }
            )
        )

        captured = capsys.readouterr()
        assert "Message: '%d'" in captured.err
