import io
import logging
import os
import time
from unittest.mock import Mock, patch

import cleo.commands.command
import cleo.events.console_command_event
import cleo.events.event_dispatcher
import cleo.io.outputs.section_output
import cleo.io.outputs.stream_output
import poetry.console.commands.run
import pytest
from cleo.io.outputs.output import Verbosity

from secrets_env.realms.poetry import SecretsEnvPlugin
from secrets_env.realms.poetry.cleo import CleoFormatter, CleoHandler, setup_output


class TestSecretsEnvPlugin:
    @pytest.fixture()
    def event(self):
        e = Mock(cleo.events.console_command_event.ConsoleCommandEvent)
        e.command = Mock(poetry.console.commands.run.RunCommand)
        e.command.name = "run"
        return e

    @pytest.fixture()
    def dispatcher(self):
        return Mock(cleo.events.event_dispatcher.EventDispatcher)

    @pytest.mark.usefixtures("_reset_logging")
    def test_load_values(self, monkeypatch: pytest.MonkeyPatch, event, dispatcher):
        monkeypatch.setattr("secrets_env.realms.poetry.setup_output", lambda _: None)
        monkeypatch.setattr(
            "secrets_env.read_values", lambda config, strict: {"VAR1": "bar"}
        )
        monkeypatch.setenv("VAR1", "foo")

        plugin = SecretsEnvPlugin()
        plugin.load_values(event, "console.command", dispatcher)

        assert os.getenv("VAR1") == "bar"

    @pytest.mark.usefixtures("_reset_logging")
    def test_load_values__skip(
        self, monkeypatch: pytest.MonkeyPatch, event, dispatcher
    ):
        func = Mock()
        monkeypatch.setattr("secrets_env.read_values", func)
        monkeypatch.setenv("VAR1", "foo")
        event.command.name = "not-related-command"

        plugin = SecretsEnvPlugin()
        plugin.load_values(event, "console.command", dispatcher)

        assert os.getenv("VAR1") == "foo"
        assert func.call_count == 0


class TestCleoHandler:
    def setup_method(self):
        self.buffer = io.StringIO()
        self.output = cleo.io.outputs.stream_output.StreamOutput(self.buffer)
        self.handler = CleoHandler(self.output)
        self.handler.setLevel(logging.NOTSET)

    @pytest.mark.parametrize(
        ("log_level", "verbosity", "has_output"),
        [
            (logging.DEBUG, Verbosity.NORMAL, False),
            (logging.DEBUG, Verbosity.VERBOSE, False),
            (logging.DEBUG, Verbosity.VERY_VERBOSE, True),
            (logging.DEBUG, Verbosity.DEBUG, True),
            (logging.INFO, Verbosity.NORMAL, False),
            (logging.INFO, Verbosity.VERBOSE, True),
            (logging.WARNING, Verbosity.QUIET, False),
            (logging.WARNING, Verbosity.NORMAL, True),
            (logging.WARNING, Verbosity.VERBOSE, True),
            (logging.ERROR, Verbosity.QUIET, True),
            (logging.ERROR, Verbosity.NORMAL, True),
            (logging.ERROR, Verbosity.VERBOSE, True),
        ],
    )
    def test_verbosity(self, log_level: int, verbosity: Verbosity, has_output: bool):
        # setup
        self.output.set_verbosity(verbosity)
        record = logging.makeLogRecord(
            {
                "name": "test",
                "levelno": log_level,
                "levelname": logging.getLevelName(log_level),
                "msg": "test message",
                "created": time.time(),
            }
        )

        # run
        self.handler.handle(record)

        # test
        self.buffer.seek(0)
        if has_output:
            assert self.buffer.read() == "test message\n"
        else:
            assert self.buffer.read() == ""

    def test_important(self):
        self.output.set_verbosity(Verbosity.QUIET)

        self.handler.handle(
            logging.makeLogRecord(
                {
                    "name": "test",
                    "levelno": logging.DEBUG,
                    "levelname": "DEBUG",
                    "msg": "<!important>test important message",
                    "created": time.time(),
                }
            )
        )

        # test
        # formatter is not installed in this test, so tag is not removed
        self.buffer.seek(0)
        assert self.buffer.read() == "<!important>test important message\n"

    def test_error(self):
        record = Mock(spec=logging.LogRecord)
        record.msg = "test msg"
        record.levelno = logging.INFO

        with patch.object(
            self.handler, "format", side_effect=RuntimeError("Test error")
        ):
            self.handler.handle(record)


class TestCleoFormatter:
    @pytest.mark.parametrize(
        ("level", "expected"),
        [
            (
                logging.ERROR,
                "<error>test <info>emphasized</info> msg with <comment>data</comment></error>",
            ),
            (
                logging.WARNING,
                "<warning>test <info>emphasized</info> msg with <comment>data</comment></warning>",
            ),
            (
                logging.INFO,
                "test <info>emphasized</info> msg with <comment>data</comment>",
            ),
            (
                logging.DEBUG,
                "[secrets.env] <debug>test <info>emphasized</info> msg with <comment>data</comment></debug>",
            ),
        ],
    )
    def test_format(self, level: int, expected: str):
        record = logging.makeLogRecord(
            {
                "name": "test",
                "levelno": level,
                "levelname": logging.getLevelName(level),
                "msg": "test <mark>emphasized</mark> msg with <data>data</data>",
                "created": time.time(),
            }
        )

        formatter = CleoFormatter()
        output = formatter.format(record)
        assert output == expected

    def test_important(self):
        record = logging.makeLogRecord(
            {
                "name": "test",
                "levelno": logging.DEBUG,
                "levelname": "DEBUG",
                "msg": "<!important>test <mark>important</mark> message",
                "created": time.time(),
            }
        )

        formatter = CleoFormatter()
        assert formatter.format(record) == (
            "[secrets.env] <debug>test <info>important</info> message</debug>"
        )


class TestSetupOutput:

    # plain styles
    BLUE = "\033[34m"
    GREEN = "\033[32m"
    WHITE = "\033[97m"
    DEFAULT = "\033[39m"

    # bold styles
    BDEFAULT = "\033[39;22m"
    BRED = "\033[31;1m"
    BYELLOW = "\033[33;1m"
    DWHITE = "\033[37;2m"

    @pytest.mark.parametrize(
        ("level", "expected"),
        [
            (
                logging.DEBUG,
                f"[secrets.env] {DWHITE}test {BDEFAULT}{BLUE}emphasized{DEFAULT}"
                f"{DWHITE} msg with {BDEFAULT}{GREEN}data{DEFAULT}{DWHITE}."
                f"{BDEFAULT}\n",
            ),
            (
                logging.INFO,
                f"test {BLUE}emphasized{DEFAULT} msg with {GREEN}data{DEFAULT}.\n",
            ),
            (
                logging.WARNING,
                f"{BYELLOW}test {BDEFAULT}{BLUE}emphasized{DEFAULT}{BYELLOW} msg "
                f"with {BDEFAULT}{GREEN}data{DEFAULT}{BYELLOW}.{BDEFAULT}\n",
            ),
            (
                logging.ERROR,
                f"{BRED}test {BDEFAULT}{BLUE}emphasized{DEFAULT}{BRED} msg with "
                f"{BDEFAULT}{GREEN}data{DEFAULT}{BRED}.{BDEFAULT}\n",
            ),
        ],
    )
    @pytest.mark.usefixtures("_reset_logging")
    def test_colored(self, level: int, expected: str):
        buffer = io.StringIO()
        output = cleo.io.outputs.stream_output.StreamOutput(
            buffer, Verbosity.DEBUG, True
        )

        setup_output(output)

        logger = logging.getLogger("secrets_env.test")
        logger.log(level, "test <mark>emphasized</mark> msg with <data>data</data>.")

        assert buffer.getvalue() == expected

    @pytest.mark.parametrize("level", [logging.DEBUG, logging.INFO, logging.ERROR])
    @pytest.mark.usefixtures("_reset_logging")
    def test_no_color(self, level: int):
        buffer = io.StringIO()
        output = cleo.io.outputs.stream_output.StreamOutput(
            buffer, Verbosity.DEBUG, False
        )

        setup_output(output)

        logger = logging.getLogger("secrets_env.test")
        logger.log(level, "test <mark>emphasized</mark> msg with <data>data</data>.")

        # check output
        # `debug` message has extra prefix so use `endswith`
        assert buffer.getvalue().endswith("test emphasized msg with data.\n")
