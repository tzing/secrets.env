import logging
import subprocess

import pytest

from secrets_env.realms.subprocess import check_output, write_output


class TestCheckOutput:
    def test_success(self, caplog: pytest.LogCaptureFixture):
        with caplog.at_level(logging.DEBUG):
            output = check_output(["printf", "\x1b[32mHello Secrets.env!\x1b[39m"])

        assert output == "\x1b[32mHello Secrets.env!\x1b[39m"
        assert "$ printf 'Hello Secrets.env!'" in caplog.text
        assert "<[stdout] Hello Secrets.env!" in caplog.text

    def test_failed(self, caplog: pytest.LogCaptureFixture):
        with (
            caplog.at_level(logging.DEBUG),
            pytest.raises(subprocess.CalledProcessError),
        ):
            check_output(
                [
                    "sh",
                    "-c",
                    """
                    echo Wow!
                    echo Ah! > /dev/stderr
                    false
                    """,
                ]
            )

        assert "< return code: 1" in caplog.text
        assert "<[stdout] Wow!" in caplog.text
        assert "<[stderr] Ah!" in caplog.text


class TestWriteOutput:
    def test_success(self, caplog: pytest.LogCaptureFixture):
        with caplog.at_level(logging.DEBUG):
            write_output("stdout", "hello world!")
            write_output("stderr", "\x1b[31mTest error\x1b[39m")
        assert "<[stdout] hello world!" in caplog.text
        assert "<[stderr] Test error" in caplog.text

    def test_skip(self, caplog: pytest.LogCaptureFixture):
        with caplog.at_level(logging.DEBUG):
            write_output("stdout", "hello world!", level=None)
        assert caplog.text == ""
