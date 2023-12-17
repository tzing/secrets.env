from pathlib import Path

import pytest

import secrets_env.config.lookup as t


class TestFindLocalConfigFile:
    @pytest.mark.parametrize(
        "filename",
        [
            ".secrets-env.toml",
            ".secrets-env.yaml",
            ".secrets-env.yml",
            ".secrets-env.json",
            "pyproject.toml",
        ],
    )
    def test_success(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        filename: str,
    ):
        monkeypatch.chdir(tmp_path)
        (tmp_path / filename).touch()

        path = t.find_local_config_file()
        assert isinstance(path, Path)

    def test_multiple(self, tmp_path: Path):
        (tmp_path / ".secrets-env.toml").touch()
        (tmp_path / ".secrets-env.json").touch()

        path = t.find_local_config_file(tmp_path)
        assert isinstance(path, Path)
        assert path.name == ".secrets-env.toml"

    def test_not_readable(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        caplog: pytest.LogCaptureFixture,
    ):
        monkeypatch.setattr(t, "is_readable_format", lambda _: False)
        (tmp_path / ".secrets-env.toml").touch()

        file = t.find_local_config_file(tmp_path)
        assert file is None
        assert (
            "the required dependency for <mark>.toml</mark> format is not installed"
            in caplog.text
        )


class TestFindGlobalConfigFiles:
    def test_success(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(Path, "is_file", lambda _: True)
        files = list(t.find_global_config_files())
        assert len(files) == 2

    def test_nothing(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(Path, "is_file", lambda _: False)
        assert list(t.find_global_config_files()) == []


def test_get_user_config_file_path():
    assert isinstance(t.get_user_config_file_path(), Path)


def test_is_readable_format():
    assert t.is_readable_format(".toml") is True
    assert t.is_readable_format(".yaml") is True
    assert t.is_readable_format(".json") is True
    assert t.is_readable_format("html") is False


def test_is_installed():
    assert t.is_installed("json") is True
    assert t.is_installed("unknown") is False
    assert t.is_installed("__error__") is False
