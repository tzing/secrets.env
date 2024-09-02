import logging

import pytest

from secrets_env.realms.subprocess import check_output, log_output


class TestLogOutput:
    def test(self, caplog: pytest.LogCaptureFixture):
        with caplog.at_level(logging.DEBUG):
            log_output("stdout", "hello world!")
            log_output("stderr", "\x1b[31mTest error\x1b[39m")
        assert "<[stdout] hello world!" in caplog.text
        assert "<[stderr] Test error" in caplog.text
