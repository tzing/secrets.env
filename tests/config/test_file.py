import builtins
import os
from pathlib import Path
from unittest.mock import mock_open

import pytest

import secrets_env.config.file as t
from secrets_env.config.types import ConfigFileMetadata


@pytest.fixture(autouse=True)
def _patch_warned_format(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setitem(vars(t.is_supportted), "warned_formats", set())


@pytest.fixture()
def example_path(repo_path: Path) -> Path:
    return repo_path / "tests" / "fixtures"


def test_import_any():
    assert t.import_any("json")
    assert t.import_any("module-not-exists", "json")
    assert t.import_any("module-not-exists") is None


class TestIsSupportted:
    def test_ok(self, caplog: pytest.LogCaptureFixture):
        meta = ConfigFileMetadata("test", "json", True)
        assert t.is_supportted(meta) is True
        assert caplog.text == ""

    def test_not_ok(self, caplog: pytest.LogCaptureFixture):
        meta = ConfigFileMetadata("test", "toml", False)
        assert t.is_supportted(meta) is False
        assert t.is_supportted(meta) is False
        assert len(caplog.records) == 1  # must only raise once


class TestFindConfigFile:
    @pytest.mark.parametrize(
        "filename",
        [
            ".secrets-env.json",
            ".secrets-env.yaml",
            ".secrets-env.yml",
            ".secrets-env.toml",
            "pyproject.toml",
        ],
    )
    def test_success_1(self, tmp_path: Path, filename: str):
        # create fake config file
        (tmp_path / filename).touch()
        (tmp_path / ".garbage").touch()

        # run test
        out = t.find_config_file(tmp_path)
        assert isinstance(out, ConfigFileMetadata)
        assert out.filename == filename
        assert out.path == (tmp_path / filename).absolute()

    def test_success_2(self, repo_path: Path):
        # use default path, and expect to find the pyproject.toml in this repo
        assert t.find_config_file() == ConfigFileMetadata(
            "pyproject.toml", "pyproject.toml", True, repo_path / "pyproject.toml"
        )

    def test_multiple(self, example_path: Path):
        # TOML is top prioritized and we must have toml parser installed in testing env
        assert t.find_config_file(example_path) == ConfigFileMetadata(
            ".secrets-env.toml",
            "toml",
            True,
            example_path / ".secrets-env.toml",
        )

    def test_not_enabled(self, monkeypatch: pytest.MonkeyPatch, example_path: Path):
        monkeypatch.setattr(
            t,
            "CONFIG_FILES",
            [
                ConfigFileMetadata(".secrets-env.toml", "toml", False),
                ConfigFileMetadata(".secrets-env.json", "json", True),
            ],
        )

        assert t.find_config_file(example_path) == ConfigFileMetadata(
            ".secrets-env.json",
            "json",
            True,
            example_path / ".secrets-env.json",
        )

    def test_no_config(self, tmp_path: Path):
        os.chdir(tmp_path)
        assert t.find_config_file() is None


class TestBuildConfigFileMetadata:
    @pytest.mark.parametrize(
        ("filename", "spec"),
        [
            ("sample.json", "json"),
            ("SAMPLE.YML", "yaml"),
            ("sample.YAML", "yaml"),
            ("Sample.Toml", "toml"),
            ("PyProject.toml", "pyproject.toml"),
        ],
    )
    def test_success(self, filename: str, spec: str):
        out = t.build_config_file_metadata(Path(filename))
        assert isinstance(out, ConfigFileMetadata)
        assert out.filename == filename
        assert out.spec == spec

    def test_fail(self, caplog: pytest.LogCaptureFixture):
        assert t.build_config_file_metadata(Path("/test/sample.dat")) is None
        assert "Failed to detect file format of <data>sample.dat</data>" in caplog.text

    def test_not_enabled(
        self, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
    ):
        monkeypatch.setattr(
            t,
            "CONFIG_FILES",
            [
                ConfigFileMetadata(".secrets-env.json", "json", False),
            ],
        )

        assert t.build_config_file_metadata(Path("sample.json")) is None
        assert "Failed to use config file <data>sample.json</data>" in caplog.text


class TestReadConfigFile:
    @pytest.mark.parametrize(
        ("filename", "spec"),
        [
            (".secrets-env.json", "json"),
            (".secrets-env.toml", "toml"),
            (".secrets-env.yaml", "yaml"),
            ("pyproject.toml", "pyproject.toml"),
        ],
    )
    def test_success(self, filename: str, spec: str, example_path: Path):
        meta = ConfigFileMetadata(filename, spec, True, example_path / filename)
        out = t.read_config_file(meta)
        assert isinstance(out, dict)
        assert isinstance(out["source"], dict)
        assert isinstance(out["secrets"], dict)

    def test_malformed(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ):
        monkeypatch.setattr(t, "read_json_file", lambda _: ["array", "data"])

        meta = ConfigFileMetadata("mock", "json", True, "mock")
        assert t.read_config_file(meta) is None
        assert "Config file is malformed" in caplog.text

    def test_runtime_error(self):
        with pytest.raises(RuntimeError):
            t.read_config_file(ConfigFileMetadata("mock", "malformed", True))


class TestReadFileErrors:
    def test_toml(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(builtins, "open", mock_open(read_data=b"["))
        assert t.read_toml_file("mocked") is None

    def test_yaml(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(builtins, "open", mock_open(read_data=b":\x0a"))
        assert t.read_yaml_file("mocked") is None

    def test_json(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(builtins, "open", mock_open(read_data=b"{"))
        assert t.read_json_file("mocked") is None
