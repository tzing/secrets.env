import pytest

import secrets_env.providers.teleport.config as t
from secrets_env.exceptions import ConfigError


def test_parse_source_config():
    assert t.parse_source_config({"app": "test"}) == {
        "proxy": None,
        "user": None,
        "app": "test",
    }


def test_parse_adapter_config():
    # success
    assert t.parse_adapter_config({"teleport": "test"}) == {
        "proxy": None,
        "user": None,
        "app": "test",
    }

    # failed - in adapter mode the configs must placed in 'teleport' section
    with pytest.raises(ConfigError):
        t.parse_adapter_config({"app": "test"})


class TestParseConfig:
    def test_success(self):
        assert t.parse_config(
            "test.teleport",
            {
                "proxy": "example.com",
                "user": "user",
                "app": "test",
            },
        ) == {
            "proxy": "example.com",
            "user": "user",
            "app": "test",
        }

    def test_shortcut(self):
        assert t.parse_config("test.teleport", "test") == {
            "proxy": None,
            "user": None,
            "app": "test",
        }

    def test_type_error(self):
        with pytest.raises(ConfigError):
            t.parse_config("test.teleport", 1234)

    def test_no_config(self):
        with pytest.raises(ConfigError):
            t.parse_config("test.teleport", {})
