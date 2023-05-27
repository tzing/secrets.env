from unittest.mock import Mock, patch

import pytest

import secrets_env.config.parser as t
from secrets_env.exceptions import AuthenticationError, ConfigError
from secrets_env.provider import ProviderBase


@pytest.fixture()
def _patch_get_provider(monkeypatch: pytest.MonkeyPatch):
    def mock_parser(data: dict):
        assert isinstance(data, dict)
        return Mock(spec=ProviderBase)

    monkeypatch.setattr("secrets_env.providers.get_provider", mock_parser)


class TestParseConfig:
    @pytest.fixture()
    def _patch_get_requests(self, monkeypatch: pytest.MonkeyPatch):
        def mock_parser(data: dict):
            assert isinstance(data, dict)
            return [{"name": "TEST", "provider": "main", "spec": "foobar"}]

        monkeypatch.setattr(t, "get_requests", mock_parser)

    @pytest.mark.usefixtures("_patch_get_provider")
    @pytest.mark.usefixtures("_patch_get_requests")
    def test_success(self):
        cfg = t.parse_config(
            {
                "source": {"url": "https://example.com/"},
                "secrets": {"TEST": "sample#foo"},
            }
        )
        assert isinstance(cfg, dict)
        assert isinstance(cfg["providers"]["main"], ProviderBase)
        assert cfg["requests"][0]["spec"] == "foobar"

    def test_no_request(self):
        cfg = t.parse_config(
            {
                "source": {"url": "https://example.com/"},
                "secrets": {},
            }
        )
        assert cfg == {"requests": []}

    def test_provider_error(self):
        with patch.object(t, "get_providers", return_value={}):
            assert (
                t.parse_config(
                    {
                        "source": {"mock": "mock"},
                        "secrets": {"TEST": "sample#foo"},
                    }
                )
                is None
            )


class TestGetProviders:
    @pytest.mark.usefixtures("_patch_get_provider")
    def test_success(self):
        result = t.get_providers(
            {
                "source": {"name": "provider 1", "data": "dummy"},
                "sources": [
                    {"data": "dummy"},
                    {"name": "provider 2", "data": "dummy"},
                ],
            }
        )
        assert len(result) == 3
        assert isinstance(result["main"], ProviderBase)
        assert isinstance(result["provider 1"], ProviderBase)
        assert isinstance(result["provider 2"], ProviderBase)

    @pytest.mark.usefixtures("_patch_get_provider")
    def test_duplicated_name(self, caplog: pytest.LogCaptureFixture):
        result = t.get_providers({"source": [{"data": "dummy"}] * 2})
        assert len(result) == 1
        assert isinstance(result["main"], ProviderBase)

        assert "Duplicated source name <data>main</data>" in caplog.text

    def test_empty(self):
        assert t.get_providers({}) == {}

    def test_parse_fail(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(t, "parse_source_item", lambda _: None)
        assert t.get_providers({"source": {"test": "dummy"}}) == {}


class TestExtractSources:
    def test_success(self):
        out = t.extract_sources(
            {
                "source": {"name": "provider 1", "data": "dummy"},
                "sources": [
                    {"data": "dummy"},
                    {"name": "provider 2", "data": "dummy"},
                    "invalid-item",
                ],
            }
        )

        assert list(out) == [
            {"name": "provider 1", "data": "dummy"},
            {"data": "dummy"},
            {"name": "provider 2", "data": "dummy"},
        ]

    def test_fail(self):
        out = t.extract_sources({"source": "invalid-item"})
        assert list(out) == []


class TestParseSourceItem:
    @pytest.mark.usefixtures("_patch_get_provider")
    def test_success_1(self):
        name, provider = t.parse_source_item({})
        assert name == "main"
        assert isinstance(provider, ProviderBase)

    @pytest.mark.usefixtures("_patch_get_provider")
    def test_success_2(self):
        name, provider = t.parse_source_item({"name": "test"})
        assert name == "test"
        assert isinstance(provider, ProviderBase)

    def test_name_error(self):
        assert t.parse_source_item({"name": object()}) is None

    def test_provider_auth_error(self, caplog: pytest.LogCaptureFixture):
        with patch(
            "secrets_env.providers.get_provider",
            side_effect=AuthenticationError("test auth error"),
        ):
            assert t.parse_source_item({}) is None
        assert "Authentication error: test auth error" in caplog.text

    def test_provider_config_error(self, caplog: pytest.LogCaptureFixture):
        with patch(
            "secrets_env.providers.get_provider",
            side_effect=ConfigError("test config error"),
        ):
            assert t.parse_source_item({}) is None
        assert "Configuration error: test config error" in caplog.text


class TestGetRequests:
    def test_success(self):
        assert t.get_requests(
            {
                "secret": {"var1": "foo#bar"},
                "secrets": {"_VAR2": {"source": "test", "key": "dummy"}},
            }
        ) == [
            {
                "name": "var1",
                "provider": "main",
                "spec": "foo#bar",
            },
            {
                "name": "_VAR2",
                "provider": "test",
                "spec": {"source": "test", "key": "dummy"},
            },
        ]

    def test_errors(self, caplog: pytest.LogCaptureFixture):
        assert t.get_requests({"secret": "not-a-dict"}) == []

        assert t.get_requests({"secret": {"-invalid": {}}}) == []
        assert "Invalid name <data>-invalid</data>." in caplog.text

        assert t.get_requests({"secret": {"test": 1234}}) == []
        assert "Invalid spec type for variable <data>test</data>." in caplog.text
