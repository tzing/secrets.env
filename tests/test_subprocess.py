import logging

import pytest

import secrets_env.subprocess as t


class TestRun:
    def test_wait(self, caplog: pytest.LogCaptureFixture):
        with caplog.at_level(logging.DEBUG):
            runner = t.Run(
                [
                    "sh",
                    "-c",
                    """
                    echo 'hello world'
                    echo 'hello stderr' > /dev/stderr
                    exit 36
                    """,
                ]
            )
            runner.wait()

        assert runner.return_code == 36
        assert runner.stdout == "hello world\n"
        assert runner.stderr == "hello stderr\n"
        assert "< hello world" in caplog.text
        assert "<[stderr] hello stderr" in caplog.text

    def test_iter_any_output(self):
        runner = t.Run(
            [
                "sh",
                "-c",
                """
                echo 'item 1'
                echo 'item 2' > /dev/stderr
                echo 'item 3'
                echo 'item 4' > /dev/stderr
                """,
            ]
        )

        assert set(runner.iter_any_output()) == {
            "item 1\n",
            "item 2\n",
            "item 3\n",
            "item 4\n",
        }
        assert runner.return_code == 0
