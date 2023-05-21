import pytest

import secrets_env.providers.teleport.config as t
from secrets_env.exceptions import ConfigError


class TestParseConfig:
    def test_success(self):
        assert t.parse_config(
            {
                "teleport": {
                    "proxy": "example.com",
                    "user": "user",
                    "app": "test",
                }
            }
        ) == {
            "proxy": "example.com",
            "user": "user",
            "app": "test",
        }

    def test_shortcut(self):
        assert t.parse_config({"teleport": "test"}) == {
            "proxy": None,
            "user": None,
            "app": "test",
        }

    def test_type_error(self):
        with pytest.raises(ConfigError):
            t.parse_config({"teleport": 1234})

    def test_no_config(self):
        with pytest.raises(ConfigError):
            t.parse_config({})
