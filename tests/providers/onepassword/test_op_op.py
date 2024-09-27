import datetime
import logging
import re
import shutil
import subprocess
from pathlib import Path
from unittest.mock import Mock

import pytest

from secrets_env.exceptions import UnsupportedError
from secrets_env.providers.onepassword.models import ItemObject
from secrets_env.providers.onepassword.op import (
    OnePasswordCliProvider,
    call_version,
    get_item,
)


@pytest.fixture
def op_path() -> Path:
    path = shutil.which("op")
    if path is None:
        pytest.skip("op is not installed")
    return Path(path)


class TestOnePasswordCliProvider:
    @pytest.fixture
    def _patch_op_path(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr("shutil.which", Mock(return_value="/usr/bin/op"))
        monkeypatch.setattr("pathlib.Path.is_file", Mock(return_value=True))

    @pytest.fixture
    def _stop_call_version(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr("secrets_env.providers.onepassword.op.call_version", Mock())

    @pytest.mark.usefixtures("_patch_op_path", "_stop_call_version")
    def test__get_item_(self, monkeypatch: pytest.MonkeyPatch):
        def _mock_get_item(op_path: Path, ref: str):
            assert op_path == Path("/usr/bin/op")
            assert ref == "sample-item"

            now = datetime.datetime.now().astimezone()
            return ItemObject(
                id="2fcbqwe9ndg175zg2dzwftvkpa",
                title="Secrets Automation Item",
                category="LOGIN",
                createdAt=now,
                updatedAt=now,
            )

        mock_get_item = Mock(side_effect=_mock_get_item)
        monkeypatch.setattr(
            "secrets_env.providers.onepassword.op.get_item", mock_get_item
        )

        provider = OnePasswordCliProvider()
        assert isinstance(provider._get_item_("sample-item"), ItemObject)
        assert isinstance(provider._get_item_("sample-item"), ItemObject)
        assert mock_get_item.call_count == 1

    @pytest.mark.usefixtures("_patch_op_path", "_stop_call_version")
    def test__get_item_error(self, monkeypatch: pytest.MonkeyPatch):
        mock_get_item = Mock(side_effect=LookupError("Test error"))
        monkeypatch.setattr(
            "secrets_env.providers.onepassword.op.get_item", mock_get_item
        )

        provider = OnePasswordCliProvider()

        with pytest.raises(LookupError):
            provider._get_item_("sample-item")
        with pytest.raises(LookupError):
            provider._get_item_("sample-item")

        assert mock_get_item.call_count == 1

    def test__get_item_unsupported(self):
        kwargs = {"name": "sample", "op-path": None}
        provider = OnePasswordCliProvider(**kwargs)
        with pytest.raises(UnsupportedError):
            provider._get_item_("sample-item")


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
