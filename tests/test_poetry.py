import io
import logging
import time
from unittest.mock import Mock, patch

import cleo.io.outputs.section_output
import cleo.io.outputs.stream_output
import pytest
from cleo.formatters.style import Style
from cleo.io.outputs.output import Verbosity

import vault2env.poetry as vault_poetry


class TestHandler:
    def setup_method(self):
        self.buffer = io.StringIO()
        self.output = cleo.io.outputs.stream_output.StreamOutput(self.buffer)
        self.handler = vault_poetry.Handler(self.output)
        self.handler.setLevel(logging.NOTSET)

    @pytest.mark.parametrize(
        ("log_level", "verbosity", "has_output"),
        [
            (logging.INFO, Verbosity.NORMAL, False),
            (logging.INFO, Verbosity.VERBOSE, True),
            (logging.WARNING, Verbosity.QUIET, False),
            (logging.WARNING, Verbosity.NORMAL, True),
            (logging.WARNING, Verbosity.VERBOSE, True),
            (logging.ERROR, Verbosity.QUIET, True),
            (logging.ERROR, Verbosity.NORMAL, True),
            (logging.ERROR, Verbosity.VERBOSE, True),
            (logging.DEBUG, Verbosity.NORMAL, False),
            (logging.DEBUG, Verbosity.VERBOSE, False),
            (logging.DEBUG, Verbosity.VERY_VERBOSE, False),
            (logging.DEBUG, Verbosity.DEBUG, True),
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
                "msg": "test <em>emphasized</em> msg with <data>data</data>",
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
        assert (
            self.format(logging.DEBUG)
            == "<debug>test <info>emphasized</info> msg with <comment>data</comment></debug>"
        )

    def test_warning(self):
        assert (
            self.format(logging.WARNING)
            == "<warning>test <info>emphasized</info> msg with <comment>data</comment></warning>"
        )

    def test_error(self):
        assert (
            self.format(logging.ERROR)
            == "<error>test <info>emphasized</info> msg with <comment>data</comment></error>"
        )


class TestHandlerWithFormatter:
    def setup_method(self):
        self.buffer = io.StringIO()

    def get_handler(self, decorated) -> logging.Handler:
        stream = cleo.io.outputs.stream_output.StreamOutput(
            self.buffer, Verbosity.DEBUG, decorated=decorated
        )

        stream.formatter.set_style("debug", Style("white"))

        handler = vault_poetry.Handler(stream)
        handler.setLevel(logging.NOTSET)
        handler.setFormatter(vault_poetry.Formatter())

        return handler

    # plain styles
    BLUE = "\033[34m"
    GREEN = "\033[32m"
    WHITE = "\033[97m"
    DEFAULT = "\033[39m"

    # bold styles
    BDEFAULT = "\033[39;22m"
    BRED = "\033[31;1m"

    @pytest.mark.parametrize(
        ("log_level", "output"),
        [
            # builtin styles
            (
                logging.INFO,
                f"test {BLUE}emphasized{DEFAULT} msg with {GREEN}data{DEFAULT}.\n",
            ),
            (
                logging.ERROR,
                f"{BRED}test {BDEFAULT}{BLUE}emphasized{DEFAULT}{BRED} msg with "
                f"{BDEFAULT}{GREEN}data{DEFAULT}{BRED}.{BDEFAULT}\n",
            ),
            # debug and warning are customized styles
            (
                logging.DEBUG,
                f"{WHITE}test {DEFAULT}{BLUE}emphasized{DEFAULT}{WHITE} msg with "
                f"{DEFAULT}{GREEN}data{DEFAULT}{WHITE}.{DEFAULT}\n",
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
                "msg": "test <em>emphasized</em> msg with <data>data</data>.",
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
                "msg": "test <em>emphasized</em> msg with <data>data</data>.",
                "created": time.time(),
            }
        )

        self.get_handler(False).handle(record)

        # check output
        self.buffer.seek(0)
        assert self.buffer.read() == "test emphasized msg with data.\n"
