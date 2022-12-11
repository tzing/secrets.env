import pytest

import secrets_env.config.parser as t
from secrets_env.providers.vault.auth.null import NoAuth


class TestParseConfig:
    @pytest.fixture()
    def _patch_source_parser(self, monkeypatch: pytest.MonkeyPatch):
        def mock_parser(data: dict):
            assert isinstance(data, dict)
            return {"url": "https://example.com", "auth": NoAuth()}

        monkeypatch.setattr(t, "parse_section_source", mock_parser)

    @pytest.fixture()
    def _patch_secrets_parser(self, monkeypatch: pytest.MonkeyPatch):
        def mock_parser(data: dict):
            assert isinstance(data, dict)
            return {"TEST": ("foo", "bar")}

        monkeypatch.setattr(t, "parse_section_secret", mock_parser)

    @pytest.mark.usefixtures("_patch_source_parser")
    @pytest.mark.usefixtures("_patch_secrets_parser")
    def test_success(self):
        cfg = t.parse_config(
            {
                "source": {"url": "https://example.com/"},
                "secrets": {"TEST": "sample#foo"},
            }
        )
        assert isinstance(cfg, dict)
        assert cfg["client"] == {"url": "https://example.com", "auth": NoAuth()}
        assert cfg["secrets"] == {"TEST": ("foo", "bar")}

    def test_skip_parsing(self):
        cfg = t.parse_config(
            {
                "source": {"url": "https://example.com/"},
                "secrets": {},
            }
        )
        assert cfg is None

    @pytest.mark.usefixtures("_patch_secrets_parser")
    def test_invalid_source(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(t, "parse_section_source", lambda _: None)

        cfg = t.parse_config(
            {
                "source": {"arg": "invalid-input"},
                "secrets": {"TEST": "sample#foo"},
            }
        )
        assert cfg is None

    @pytest.mark.usefixtures("_patch_source_parser")
    def test_invalid_secret(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(t, "parse_section_source", lambda _: None)

        cfg = t.parse_config(
            {
                "source": {"url": "https://example.com/"},
                "secrets": {"@arg": "invalid-input"},
            }
        )
        assert cfg is None


def test_parse_section_secret(caplog: pytest.LogCaptureFixture):
    assert t.parse_section_secret(
        {
            "var1": "foo#bar",
            "_VAR2": {"path": "foo", "field": "bar"},
            "var3:invalid_name": "foo#bar",
        }
    ) == {
        "var1": ("foo", "bar"),
        "_VAR2": ("foo", "bar"),
    }

    assert (
        "Invalid environment variable name <data>var3:invalid_name</data>."
        in caplog.text
    )
