import vault2env.poetry as vault_poetry
import logging
import time


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
