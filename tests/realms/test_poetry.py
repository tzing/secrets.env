import contextlib
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
from cleo.formatters.style import Style
from cleo.io.outputs.output import Verbosity

import secrets_env.realms.poetry as plugin


@pytest.mark.usefixtures("_reset_logging")
class TestSecretsEnvPlugin:
    def setup_method(self):
        self.plugin = plugin.SecretsEnvPlugin()

        self.event = Mock(spec=cleo.events.console_command_event.ConsoleCommandEvent)
        self.event.command = Mock(spec=poetry.console.commands.run.RunCommand)
        self.event.command.name = "run"

        self.dispatcher = Mock(spec=cleo.events.event_dispatcher.EventDispatcher)

    def teardown_method(self):
        # reset env
        with contextlib.suppress(KeyError):
            os.environ.pop("VAR1")

    @pytest.fixture()
    def patch_setup_output(self):
        with patch.object(self.plugin, "setup_output") as mock:
            yield mock

    @pytest.mark.usefixtures("patch_setup_output")
    def test_load_secret(self):
        with patch("secrets_env.read_values", return_value={"VAR1": "test"}):
            self.plugin.load_secret(self.event, "test", self.dispatcher)
        assert os.getenv("VAR1") == "test"

    def test_load_secret_not_related_command(self, patch_setup_output: Mock):
        # command is not `run` or `shell`
        self.event.command = Mock(spec=cleo.commands.command.Command)

        # if it does not exit in the beginning, then it triggerred errors at
        # setup_output
        patch_setup_output.side_effect = RuntimeError("should not raised")
        self.plugin.load_secret(self.event, "test", self.dispatcher)

    def test_setup_output(self):
        # NOTE: text coloring test are in TestTextColoring
        buffer = io.StringIO()
        output = cleo.io.outputs.stream_output.StreamOutput(buffer, decorated=False)

        self.plugin.setup_output(output)
        logging.getLogger("secrets_env.test").error("test message")

        buffer.seek(0)
        assert buffer.read() == "test message\n"


class TestHandler:
    def setup_method(self):
        self.buffer = io.StringIO()
        self.output = cleo.io.outputs.stream_output.StreamOutput(self.buffer)
        self.handler = plugin.CleoHandler(self.output)
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


class TestFormatter:
    def setup_method(self):
        self.formatter = plugin.CleoFormatter()

    def format(self, level: int) -> str:
        record = logging.makeLogRecord(
            {
                "name": "test",
                "levelno": level,
                "levelname": logging.getLevelName(level),
                "msg": "test <mark>emphasized</mark> msg with <data>data</data>",
                "created": time.time(),
            }
        )

        return self.formatter.format(record)

    def test_info(self):
        assert (
            self.format(logging.INFO)
            == "test <info>emphasized</info> msg with <comment>data</comment>"
        )

    def test_debug(self):
        assert self.format(logging.DEBUG) == (
            "[secrets_env] <debug>test <info>emphasized</info> msg with <comment>"
            "data</comment></debug>"
        )

    def test_warning(self):
        assert self.format(logging.WARNING) == (
            "<warning>test <info>emphasized</info> msg with <comment>data"
            "</comment></warning>"
        )

    def test_error(self):
        assert self.format(logging.ERROR) == (
            "<error>test <info>emphasized</info> msg with <comment>data"
            "</comment></error>"
        )

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
        assert self.formatter.format(record) == (
            "[secrets_env] <debug>test <info>important</info> message</debug>"
        )


class TestTextColoring:
    def setup_method(self):
        self.buffer = io.StringIO()

    def get_handler(self, decorated) -> logging.Handler:
        output = cleo.io.outputs.stream_output.StreamOutput(
            self.buffer, Verbosity.DEBUG, decorated=decorated
        )

        output.formatter.set_style("debug", Style("light_gray", options=["dark"]))
        output.formatter.set_style("warning", Style("yellow"))

        handler = plugin.CleoHandler(output)
        handler.setLevel(logging.NOTSET)
        handler.setFormatter(plugin.CleoFormatter())

        return handler

    # plain styles
    BLUE = "\033[34m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    WHITE = "\033[97m"
    DEFAULT = "\033[39m"

    # bold styles
    BDEFAULT = "\033[39;22m"
    BRED = "\033[31;1m"
    DWHITE = "\033[37;2m"

    @pytest.mark.parametrize(
        ("log_level", "output"),
        [
            (
                logging.DEBUG,
                f"[secrets_env] {DWHITE}test {BDEFAULT}{BLUE}emphasized{DEFAULT}"
                f"{DWHITE} msg with {BDEFAULT}{GREEN}data{DEFAULT}{DWHITE}."
                f"{BDEFAULT}\n",
            ),
            (
                logging.INFO,
                f"test {BLUE}emphasized{DEFAULT} msg with {GREEN}data{DEFAULT}.\n",
            ),
            (
                logging.WARNING,
                f"{YELLOW}test {DEFAULT}{BLUE}emphasized{DEFAULT}{YELLOW} msg "
                f"with {DEFAULT}{GREEN}data{DEFAULT}{YELLOW}.{DEFAULT}\n",
            ),
            (
                logging.ERROR,
                f"{BRED}test {BDEFAULT}{BLUE}emphasized{DEFAULT}{BRED} msg with "
                f"{BDEFAULT}{GREEN}data{DEFAULT}{BRED}.{BDEFAULT}\n",
            ),
        ],
    )
    def test_color(self, log_level: int, output: str):
        # send log
        record = logging.makeLogRecord(
            {
                "name": "test",
                "levelno": log_level,
                "levelname": logging.getLevelName(log_level),
                "msg": "test <mark>emphasized</mark> msg with <data>data</data>.",
                "created": time.time(),
            }
        )

        self.get_handler(True).handle(record)

        # check output
        # compare in bytes for error message readability
        self.buffer.seek(0)
        assert self.buffer.read().encode() == output.encode()

    @pytest.mark.parametrize(
        ("log_level"), [logging.DEBUG, logging.INFO, logging.ERROR]
    )
    def test_no_color(self, log_level: int):
        # send log
        record = logging.makeLogRecord(
            {
                "name": "test",
                "levelno": log_level,
                "levelname": logging.getLevelName(log_level),
                "msg": "test <mark>emphasized</mark> msg with <data>data</data>.",
                "created": time.time(),
            }
        )

        self.get_handler(False).handle(record)

        # check output
        # `debug` message has extra prefix
        self.buffer.seek(0)
        assert self.buffer.read().endswith("test emphasized msg with data.\n")
