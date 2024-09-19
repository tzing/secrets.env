import logging
import re
import shutil
import subprocess
from pathlib import Path
from unittest.mock import Mock

import pytest

from secrets_env.providers.onepassword.cli import OnePasswordCliProvider, call_version


@pytest.fixture
def op_path() -> Path:
    path = shutil.which("op")
    if path is None:
        pytest.skip("op is not installed")
    return Path(path)


class TestCallVersion:
    @pytest.fixture(autouse=True)
    def _reset_cache(self):
        yield
        call_version.cache_clear()

    def test_success(self, monkeypatch: pytest.MonkeyPatch):
        mock_check_output = Mock(return_value=b"2.30.0")
        monkeypatch.setattr(
            "secrets_env.providers.onepassword.cli.check_output", mock_check_output
        )

        call_version(Path("/usr/bin/op"))

        mock_check_output.assert_called_once_with(["/usr/bin/op", "--version"])

    def test_fail(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(
            "secrets_env.providers.onepassword.cli.check_output",
            Mock(side_effect=subprocess.CalledProcessError(1, "op")),
        )

        with pytest.raises(RuntimeError):
            call_version(Path("/usr/bin/op"))

    def test_integration(self, caplog: pytest.LogCaptureFixture, op_path: Path):
        with caplog.at_level(logging.DEBUG):
            call_version(op_path)
        assert re.match(r"<\[stdout\] \d+\.\d+\.\d+", caplog.records[-1].message)
