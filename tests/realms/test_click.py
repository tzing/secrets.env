import logging

import click.testing
import pytest

from secrets_env.realms.click import (
    ClickHandler,
    ColorFormatter,
    SecretsEnvFilter,
    SecretsEnvFormatter,
    with_output_options,
)


class TestWithOutputOptions:
    @click.command()
    @with_output_options
    def sample_command():
        for logger in (
            logging.getLogger("secrets_env.foo"),
            logging.getLogger("mock.bar"),
        ):
            logger.debug("test debug msg")
            logger.info("test info msg")
            logger.warning("test warning msg")
            logger.info("<!important>test important info msg")

    @pytest.fixture()
    def runner(self):
        return click.testing.CliRunner()

    @pytest.mark.usefixtures("_reset_logging")
    def test_default(self, runner: click.testing.CliRunner):
        res = runner.invoke(self.sample_command)
        assert res.exit_code == 0

        assert "[secrets_env] test info msg" in res.output
        assert "[secrets_env] test important info msg" in res.output
        assert "[mock] test warning msg" in res.output

        assert "[secrets_env] test debug msg" not in res.output
        assert "[mock] test info msg" not in res.output

    @pytest.mark.usefixtures("_reset_logging")
    def test_quiet(self, runner: click.testing.CliRunner):
        res = runner.invoke(self.sample_command, ["-q"])
        assert res.exit_code == 0

        assert "[secrets_env] test warning msg" in res.output
        assert "[secrets_env] test important info msg" in res.output
        assert "[mock] test warning msg" in res.output

        assert "[secrets_env] test info msg" not in res.output
        assert "[mock] test info msg" not in res.output

    @pytest.mark.usefixtures("_reset_logging")
    def test_verbose(self, runner: click.testing.CliRunner):
        res = runner.invoke(self.sample_command, ["-v"])
        assert res.exit_code == 0

        assert "[secrets_env] test debug msg" in res.output
        assert "[mock] test warning msg" in res.output

        assert "[mock] test info msg" not in res.output

    @pytest.mark.usefixtures("_reset_logging")
    def test_debug(self, runner: click.testing.CliRunner):
        res = runner.invoke(self.sample_command, ["-vv"])
        assert res.exit_code == 0

        assert "[secrets_env] test debug msg" in res.output
        assert "[mock] test debug msg" in res.output
