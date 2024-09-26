import logging
import re
import shutil
import subprocess
from pathlib import Path
from unittest.mock import Mock

import pytest

from secrets_env.providers.onepassword.op import (
    OnePasswordCliProvider,
    call_version,
    get_item,
)
from secrets_env.providers.onepassword.models import ItemObject


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
        mock_check_output = Mock()
        monkeypatch.setattr(
            "secrets_env.providers.onepassword.op.check_output", mock_check_output
        )

        call_version(Path("/usr/bin/op"))

        mock_check_output.assert_called_once_with(["/usr/bin/op", "--version"])

    def test_fail(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(
            "secrets_env.providers.onepassword.op.check_output",
            Mock(side_effect=subprocess.CalledProcessError(1, "op")),
        )

        with pytest.raises(RuntimeError):
            call_version(Path("/usr/bin/op"))

    def test_integration(self, caplog: pytest.LogCaptureFixture, op_path: Path):
        with caplog.at_level(logging.DEBUG):
            call_version(op_path)
        assert re.match(r"<\[stdout\] \d+\.\d+\.\d+", caplog.records[-1].message)


class TestGetItem:
    def test_success(self, monkeypatch: pytest.MonkeyPatch):
        mock_check_output = Mock(
            return_value="""
            {
                "id": "2fcbqwe9ndg175zg2dzwftvkpa",
                "title": "Secrets Automation Item",
                "category": "LOGIN",
                "createdAt": "2021-04-10T17:20:05.98944527Z",
                "updatedAt": "2021-04-13T17:20:05.989445411Z"
            }
            """
        )
        monkeypatch.setattr(
            "secrets_env.providers.onepassword.op.check_output", mock_check_output
        )

        item = get_item(op_path=Path("/usr/bin/op"), ref="sample-item")
        assert isinstance(item, ItemObject)

    def test_fail(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(
            "secrets_env.providers.onepassword.op.check_output",
            Mock(
                side_effect=subprocess.CalledProcessError(
                    1, "op", stderr="[ERROR] 2024/02/30 12:34:56 Test error\n"
                )
            ),
        )
        with pytest.raises(LookupError, match="^Test error$"):
            get_item(op_path=Path("/usr/bin/op"), ref="sample-item")
