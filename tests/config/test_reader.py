from pathlib import Path

import pytest

import secrets_env.config.reader as t
from secrets_env.exceptions import ConfigError, UnsupportedError


class TestRead:
    @pytest.mark.parametrize(
        ("filename", "content"),
        [
            ("config.toml", ""),
            ("config.yaml", ""),
            ("config.yml", ""),
            ("config.json", "{}"),
            ("pyproject.toml", "[tool.not-related]"),
        ],
    )
    def test_success(self, tmp_path: Path, filename: str, content: str):
        filepath = tmp_path / filename
        filepath.write_text(content)
        assert t.read(filepath) == {}

    def test_file_not_found(self, tmp_path: Path):
        with pytest.raises(ConfigError):
            t.read(tmp_path / "config.toml")

    def test_unsupported_format(self, tmp_path: Path):
        filepath = tmp_path / "config.txt"
        filepath.touch()
        with pytest.raises(UnsupportedError):
            t.read(filepath)

    def test_invalid_content(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(t, "read_toml_file", lambda _: "not a dict")
        monkeypatch.setattr(Path, "is_file", lambda _: True)

        with pytest.raises(
            ConfigError, match="Expect key-value pairs in the config file"
        ):
            t.read("/test/config.toml")

    def test_invalid_toml(self, tmp_path: Path, caplog: pytest.LogCaptureFixture):
        filepath = tmp_path / "config.toml"
        filepath.write_text("[]")
        assert t.read_toml_file(filepath) is None
        assert "Failed to parse TOML file" in caplog.text

    def test_invalid_yaml(self, tmp_path: Path, caplog: pytest.LogCaptureFixture):
        filepath = tmp_path / "config.yaml"
        filepath.write_text(":")
        assert t.read_yaml_file(filepath) is None
        assert "Failed to parse YAML file" in caplog.text

    def test_invalid_json(self, tmp_path: Path, caplog: pytest.LogCaptureFixture):
        filepath = tmp_path / "config.json"
        filepath.write_text("[")
        assert t.read_json_file(filepath) is None
        assert "Failed to parse JSON file" in caplog.text
