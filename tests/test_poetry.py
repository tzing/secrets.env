import io
import logging
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

import vault2env
import vault2env.poetry as vault_poetry
from vault2env.config import ConfigSpec, SecretResource


class TestVault2EnvPlugin:
    def setup_method(self):
        self.plugin = vault_poetry.Vault2EnvPlugin()

        self.event = Mock(spec=cleo.events.console_command_event.ConsoleCommandEvent)
        self.event.command = Mock(spec=poetry.console.commands.run.RunCommand)

        self.dispatcher = Mock(spec=cleo.events.event_dispatcher.EventDispatcher)

    def teardown_method(self):
        logger = logging.getLogger("vault2env")
        logger.setLevel(logging.NOTSET)
        logger.propagate = True
        for h in list(logger.handlers):
            logger.removeHandler(h)

    @pytest.fixture()
    def patch_setup_output(self):
        with patch.object(self.plugin, "setup_output") as mock:
            yield mock

    @pytest.fixture()
    def _patch_load_config(self):
        with patch(
            "vault2env.load_config",
            return_value=ConfigSpec(
                url="https://example.com/",
                auth=vault2env.TokenAuth("ex@mp1e"),
                secret_specs={
                    "VAR1": SecretResource("key1", "example"),
                    "VAR2": SecretResource("key2", "example"),
                },
            ),
        ):
            yield

    @pytest.mark.usefixtures("patch_setup_output")
    @pytest.mark.usefixtures("_patch_load_config")
    def test_load_secret(self):
        with patch(
            "vault2env.KVReader.get_values",
            return_value={
                SecretResource("key1", "example"): "foo",
                SecretResource("key2", "example"): "bar",
            },
        ):
            self.plugin.load_secret(self.event, "test", self.dispatcher)

    @pytest.mark.usefixtures("patch_setup_output")
    @pytest.mark.usefixtures("_patch_load_config")
    def test_load_secret_partial(self):
        with patch(
            "vault2env.KVReader.get_values",
            return_value={
                # no key2
                SecretResource("key1", "example"): "foo",
            },
        ):
            self.plugin.load_secret(self.event, "test", self.dispatcher)

    def test_load_secret_no_config(self):
        with patch("vault2env.load_config", return_value=None):
            self.plugin.load_secret(self.event, "test", self.dispatcher)

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
        logging.getLogger("vault2env.test").error("test message")

        buffer.seek(0)
        assert buffer.read() == "test message\n"


class TestHandler:
    def setup_method(self):
        self.buffer = io.StringIO()
        self.output = cleo.io.outputs.stream_output.StreamOutput(self.buffer)
        self.handler = vault_poetry.Handler(self.output)
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

    def test_error(self):
        record = Mock(spec=logging.LogRecord)
        with patch.object(
            self.handler, "format", side_effect=RuntimeError("Test error")
        ):
            self.handler.handle(record)


class TestFormatter:
    def setup_method(self):
        self.formatter = vault_poetry.Formatter()

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
            "[vault2env] <debug>test <info>emphasized</info> msg with <comment>"
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


class TestTextColoring:
    def setup_method(self):
        self.buffer = io.StringIO()

    def get_handler(self, decorated) -> logging.Handler:
        output = cleo.io.outputs.stream_output.StreamOutput(
            self.buffer, Verbosity.DEBUG, decorated=decorated
        )

        output.formatter.set_style("debug", Style("white"))
        output.formatter.set_style("warning", Style("yellow"))

        handler = vault_poetry.Handler(output)
        handler.setLevel(logging.NOTSET)
        handler.setFormatter(vault_poetry.Formatter())

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

    @pytest.mark.parametrize(
        ("log_level", "output"),
        [
            (
                logging.DEBUG,
                f"[vault2env] {WHITE}test {DEFAULT}{BLUE}emphasized{DEFAULT}"
                f"{WHITE} msg with {DEFAULT}{GREEN}data{DEFAULT}{WHITE}.{DEFAULT}\n",
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
