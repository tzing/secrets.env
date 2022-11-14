import builtins
import os
from pathlib import Path
from unittest.mock import mock_open

import pytest

import secrets_env.config.file as t


@pytest.fixture()
def fixture_dir(repo_path: Path) -> Path:
    return repo_path / "tests" / "fixtures"


class TestConfigFile:
    @pytest.mark.parametrize(
        ("filename", "format_"),
        [
            (".secrets-env.json", "json"),
            (".secrets-env.yaml", "yaml"),
            (".secrets-env.yml", "yaml"),
            (".secrets-env.toml", "toml"),
            ("pyproject.toml", "pyproject.toml"),
        ],
    )
    def test_success(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        filename: str,
        format_: str,
    ):
        monkeypatch.chdir(tmp_path)

        # create fake config file
        (tmp_path / filename).touch()

        # run test
        spec = t.find_config_file()
        assert spec.filename == filename
        assert spec.format == format_
        assert spec.path == tmp_path / filename

    def test_multiple(self, fixture_dir: Path):
        # TOML is top prioritized and we must have toml parser installed in testing env
        spec = t.find_config_file(fixture_dir)
        assert spec.filename == ".secrets-env.toml"
        assert spec.format == "toml"
        assert spec.path == fixture_dir / ".secrets-env.toml"


def test_check_installed():
    assert t.check_installed("json") is True
    assert t.check_installed("module-not-exists", "json") is True
    assert t.check_installed("module-not-exists") is False


def test_is_supportted(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
):
    monkeypatch.setitem(t.LANGUAGE_ENABLED, "test-lang", False)
    assert t.is_supportted("json") is True
    assert t.is_supportted("test-lang") is False
    assert t.is_supportted("test-lang") is False
    assert len(caplog.records) == 1
