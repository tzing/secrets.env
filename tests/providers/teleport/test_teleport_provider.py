import re
from pathlib import Path
from unittest.mock import Mock

import pytest

import secrets_env.providers.teleport.provider as t
from secrets_env.exceptions import ConfigError, ValueNotFound
from secrets_env.providers.teleport.helper import AppConnectionInfo


@pytest.fixture()
def conn_info():
    return AppConnectionInfo(
        uri="https://example.com",
        ca=b"subject=/C=XX/L=Default City/O=Test\n-----MOCK CERTIFICATE-----",
        cert=b"-----MOCK CERTIFICATE-----",
        key=b"-----MOCK PRIVATE KEY-----",
    )


class TestTeleportProvider:
    @pytest.fixture()
    def provider(self):
        return t.TeleportProvider(proxy=None, cluster=None, user=None, app="test")

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
        self, monkeypatch: pytest.MonkeyPatch, provider, conn_info, field, expect
    ):
        monkeypatch.setattr(t, "get_connection_info", lambda _: conn_info)
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
        self, monkeypatch: pytest.MonkeyPatch, provider, conn_info, field, expect
    ):
        monkeypatch.setattr(t, "get_connection_info", lambda _: conn_info)
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
        with pytest.raises(TypeError):
            t.parse_spec(1234)


def test_get_ca(conn_info):
    # path
    p = t.get_ca(conn_info, "path")
    assert isinstance(p, str)
    assert Path(p).is_file()

    # pem
    d = t.get_ca(conn_info, "pem")
    assert isinstance(d, str)
    assert d == "subject=/C=XX/L=Default City/O=Test\n-----MOCK CERTIFICATE-----"

    # no CA
    conn_info_no_ca = AppConnectionInfo(
        uri="https://example.com",
        ca=None,
        cert=b"-----MOCK CERTIFICATE-----",
        key=b"-----MOCK PRIVATE KEY-----",
    )
    with pytest.raises(ValueNotFound):
        t.get_ca(conn_info_no_ca, "path")

    # make linter happy
    with pytest.raises(RuntimeError):
        t.get_ca(conn_info, "no-this-format")
