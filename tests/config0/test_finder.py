from pathlib import Path

import pytest

import secrets_env.config0.finder as t


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
        assert spec
        assert spec.filename == filename
        assert spec.format == format_
        assert spec.path == tmp_path / filename

    def test_multiple(self, fixture_dir: Path):
        # TOML is top prioritized and we must have toml parser installed in testing env
        spec = t.find_config_file(fixture_dir)
        assert spec
        assert spec.filename == ".secrets-env.toml"
        assert spec.format == "toml"
        assert spec.path == fixture_dir / ".secrets-env.toml"

    def test_not_support(self, monkeypatch: pytest.MonkeyPatch, fixture_dir: Path):
        monkeypatch.setattr(t, "LANGUAGE_ENABLED", {"json": True, "toml": False})
        monkeypatch.setattr(
            t,
            "CONFIG_FILE_FORMATS",
            [
                t.ConfigFileSpec(".secrets-env.toml", "toml"),
                t.ConfigFileSpec(".secrets-env.json", "json"),
            ],
        )

        spec = t.find_config_file(fixture_dir)
        assert spec
        assert spec.format == "json"

    def test_not_found(self, tmp_path: Path):
        assert t.find_config_file(tmp_path) is None


class TestGetConfigFileMetadata:
    @pytest.mark.parametrize(
        ("filename", "format_"),
        [
            ("sample.json", "json"),
            ("SAMPLE.YML", "yaml"),
            ("sample.YAML", "yaml"),
            ("Sample.Toml", "toml"),
            ("pyproject.toml", "pyproject.toml"),
        ],
    )
    def test_success(self, tmp_path: Path, filename: str, format_: str):
        path = tmp_path / filename
        path.touch()  # ensure file exist

        spec = t.get_config_file_metadata(tmp_path / filename)
        assert spec
        assert spec.filename == filename
        assert spec.format == format_

    def test_not_exist(self):
        assert t.get_config_file_metadata(Path("/data/no-this-config")) is None

    def test_unknown_format(self, tmp_path: Path, caplog: pytest.LogCaptureFixture):
        path = tmp_path / "sample.unknown-type"
        path.touch()  # ensure file exist

        assert t.get_config_file_metadata(path) is None
        assert (
            "Failed to detect file format for <data>sample.unknown-type</data>"
        ) in caplog.text

    def test_not_support(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        caplog: pytest.LogCaptureFixture,
    ):
        monkeypatch.setattr(t, "is_supportted", lambda _: False)

        path = tmp_path / "sample.json"
        path.touch()  # ensure file exist

        assert t.get_config_file_metadata(path) is None
        assert "Failed to read <data>sample.json</data>" in caplog.text


def test_check_installed():
    assert t.check_installed("json") is True
    assert t.check_installed("module-not-exists", "json") is True
    assert t.check_installed("module-not-exists") is False
    assert t.check_installed("module-not-exists.nested") is False


def test_is_supportted(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
):
    monkeypatch.setitem(t.LANGUAGE_ENABLED, "test-lang", False)
    assert t.is_supportted("json") is True
    assert t.is_supportted("test-lang") is False
    assert t.is_supportted("test-lang") is False
    assert len(caplog.records) == 1
