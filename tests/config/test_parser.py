from unittest.mock import Mock, patch

import pytest

import secrets_env.config.parser as t
from secrets_env.exceptions import AuthenticationError
from secrets_env.provider import ProviderBase


class TestParseConfig:
    @pytest.fixture()
    def _patch_get_provider(self, monkeypatch: pytest.MonkeyPatch):
        def mock_parser(data: dict):
            assert isinstance(data, dict)
            return Mock(spec=ProviderBase)

        monkeypatch.setattr("secrets_env.providers.get_provider", mock_parser)

    @pytest.fixture()
    def _patch_secrets_parser(self, monkeypatch: pytest.MonkeyPatch):
        def mock_parser(data: dict):
            assert isinstance(data, dict)
            return {"TEST": ("foo", "bar")}

        monkeypatch.setattr(t, "parse_section_secret", mock_parser)

    @pytest.mark.usefixtures("_patch_get_provider")
    @pytest.mark.usefixtures("_patch_secrets_parser")
    def test_success(self):
        cfg = t.parse_config(
            {
                "source": {"url": "https://example.com/"},
                "secrets": {"TEST": "sample#foo"},
            }
        )
        assert isinstance(cfg, dict)
        assert isinstance(cfg["client"], ProviderBase)
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
    def test_auth_error(self):
        with patch(
            "secrets_env.providers.get_provider",
            side_effect=AuthenticationError("test"),
        ):
            cfg = t.parse_config(
                {
                    "source": {"mock": "mock"},
                    "secrets": {"TEST": "sample#foo"},
                }
            )
        assert cfg is None

    @pytest.mark.usefixtures("_patch_secrets_parser")
    def test_config_error(self):
        cfg = t.parse_config(
            {
                "source": {"arg": "invalid-input"},
                "secrets": {"TEST": "sample#foo"},
            }
        )
        assert cfg is None

    @pytest.mark.usefixtures("_patch_get_provider")
    def test_invalid_secret(self):
        cfg = t.parse_config(
            {
                "source": {"url": "https://example.com/"},
                "secrets": {"@arg": "invalid-input"},
            }
        )
        assert cfg is None


class TestParseSectionSecret:
    def test_success(self):
        assert t.parse_section_secret(
            {
                "var1": "foo#bar",
                "_VAR2": {"path": "foo", "field": "bar"},
            }
        ) == {
            "var1": "foo#bar",
            "_VAR2": {"path": "foo", "field": "bar"},
        }

    def test_empty(self, caplog: pytest.LogCaptureFixture):
        assert t.parse_section_secret(
            {
                "EXAMPLE": "foo#bar",
                "TEST": "",
            }
        ) == {"EXAMPLE": "foo#bar"}
        assert "No source spec for variable <data>TEST</data>." in caplog.text

    def test_type(self, caplog: pytest.LogCaptureFixture):
        assert t.parse_section_secret(
            {
                "EXAMPLE": "foo#bar",
                "TEST": 1234,
            }
        ) == {"EXAMPLE": "foo#bar"}
        assert "Invalid source spec type for variable <data>TEST</data>." in caplog.text
