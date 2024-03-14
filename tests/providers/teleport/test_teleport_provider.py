import re
from pathlib import Path
from unittest.mock import Mock

import pytest

import secrets_env.providers.teleport.provider as t
from secrets_env.exceptions import ConfigError, ValueNotFound
from secrets_env.providers.teleport.config import (
    TeleportConnectionParameter,
    TeleportUserConfig,
)


class TestTeleportProvider:
    @pytest.fixture()
    def provider(self):
        return t.TeleportProvider(config=TeleportUserConfig(app="test"))

    def test_type(self, provider):
        assert provider.type == "teleport"

    @pytest.mark.parametrize(
        ("field", "expect"),
        [
            ("CA", b"subject=/C=XX/L=Default City/O=Test\n-----MOCK CERTIFICATE-----"),
            ("CERT", b"-----MOCK CERTIFICATE-----"),
            ("KEY", b"-----MOCK PRIVATE KEY-----"),
            ("cert+KEY", b"-----MOCK CERTIFICATE-----\n-----MOCK PRIVATE KEY-----"),
        ],
    )
    def test_get_path(
        self, monkeypatch: pytest.MonkeyPatch, provider, conn_param, field, expect
    ):
        monkeypatch.setattr(
            TeleportUserConfig, "get_connection_param", lambda _: conn_param
        )
        path = provider.get({"field": field, "format": "path"})
        assert isinstance(path, str)
        assert Path(path).is_file()
        assert Path(path).read_bytes() == expect

    @pytest.mark.parametrize(
        ("field", "expect"),
        [
            ("URI", "https://example.com"),
            ("CA", "subject=/C=XX/L=Default City/O=Test\n-----MOCK CERTIFICATE-----"),
            ("CERT", "-----MOCK CERTIFICATE-----"),
            ("KEY", "-----MOCK PRIVATE KEY-----"),
            ("cert+KEY", "-----MOCK CERTIFICATE-----\n-----MOCK PRIVATE KEY-----"),
        ],
    )
    def test_get_pem(
        self, monkeypatch: pytest.MonkeyPatch, provider, conn_param, field, expect
    ):
        monkeypatch.setattr(
            TeleportUserConfig, "get_connection_param", lambda _: conn_param
        )
        data = provider.get({"field": field, "format": "pem"})
        assert isinstance(data, str)
        assert data == expect

    def test_get_error(self, monkeypatch: pytest.MonkeyPatch, provider):
        monkeypatch.setattr(
            t, "parse_spec", lambda _: Mock(spec=t.OutputSpec, field="unknown")
        )
        with pytest.raises(
            ConfigError, match=re.escape("Invalid value spec: {'mock': 'mocked'}")
        ):
            provider.get({"mock": "mocked"})


class TestParseSpec:
    def test_success(self):
        assert t.parse_spec("ca") == t.OutputSpec("ca", "path")
        assert t.parse_spec({"field": "ca"}) == t.OutputSpec("ca", "path")
        assert t.parse_spec({"field": "ca", "format": "pem"}) == t.OutputSpec(
            "ca", "pem"
        )

    def test_failed(self):
        with pytest.raises(
            ConfigError, match=re.escape("Invalid field (secrets.VAR.field): invalid")
        ):
            t.parse_spec({"field": "invalid"})

        with pytest.raises(
            ConfigError, match=re.escape("Invalid format (secrets.VAR.format): invalid")
        ):
            t.parse_spec({"field": "ca", "format": "invalid"})

    def test_type_error(self):
        with pytest.raises(
            ConfigError,
            match=re.escape("Expect dict for secrets path spec, got int"),
        ):
            t.parse_spec(1234)


def test_get_ca(conn_param):
    # path
    p = t.get_ca(conn_param, "path")
    assert isinstance(p, str)
    assert Path(p).is_file()

    # pem
    d = t.get_ca(conn_param, "pem")
    assert isinstance(d, str)
    assert d == "subject=/C=XX/L=Default City/O=Test\n-----MOCK CERTIFICATE-----"

    # no CA
    conn_param_no_ca = TeleportConnectionParameter(
        uri="https://example.com",
        ca=None,
        cert=b"-----MOCK CERTIFICATE-----",
        key=b"-----MOCK PRIVATE KEY-----",
    )
    with pytest.raises(ValueNotFound):
        t.get_ca(conn_param_no_ca, "path")

    # make linter happy
    with pytest.raises(RuntimeError):
        t.get_ca(conn_param, "no-this-format")
