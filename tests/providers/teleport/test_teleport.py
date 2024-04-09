from pathlib import Path
from unittest.mock import Mock, PropertyMock

import pytest

from secrets_env.exceptions import NoValue
from secrets_env.provider import Request
from secrets_env.providers.teleport import TeleportProvider, TeleportRequestSpec, get_ca
from secrets_env.providers.teleport.config import TeleportConnectionParameter


class TestTeleportProvider:
    @pytest.fixture()
    def provider(
        self, monkeypatch: pytest.MonkeyPatch, conn_param: TeleportConnectionParameter
    ):
        monkeypatch.setattr(
            TeleportProvider, "connection_param", PropertyMock(return_value=conn_param)
        )
        return TeleportProvider(app="test")

    def test_get_uri(self, provider: TeleportProvider):
        assert provider(Request(name="test", value="uri")) == "https://example.com"

    def test_get_ca(self, provider: TeleportProvider):
        expect = "subject=/C=XX/L=Default City/O=Test\n-----MOCK CERTIFICATE-----"
        assert provider(Request(name="test", field="ca", format="pem")) == expect
        with open(provider(Request(name="test", value="ca"))) as fd:
            assert fd.read() == expect

    def test_get_cert(self, provider: TeleportProvider):
        expect = "-----MOCK CERTIFICATE-----"
        assert provider(Request(name="test", field="cert", format="pem")) == expect
        with open(provider(Request(name="test", value="cert"))) as fd:
            assert fd.read() == expect

    def test_get_key(self, provider: TeleportProvider):
        expect = "-----MOCK PRIVATE KEY-----"
        assert provider(Request(name="test", field="key", format="pem")) == expect
        with open(provider(Request(name="test", value="key"))) as fd:
            assert fd.read() == expect

    def test_get_cert_and_key(self, provider: TeleportProvider):
        expect = "-----MOCK CERTIFICATE-----\n-----MOCK PRIVATE KEY-----"
        assert provider(Request(name="test", field="cert+key", format="pem")) == expect
        with open(provider(Request(name="test", value="cert+key"))) as fd:
            assert fd.read() == expect

    def test_get_invalid(self, monkeypatch: pytest.MonkeyPatch):
        spec = Mock(TeleportRequestSpec)
        spec.field = "unknown"
        monkeypatch.setattr(
            "secrets_env.providers.teleport.TeleportRequestSpec",
            Mock(return_value=spec),
        )

        provider = TeleportProvider(app="test")
        with pytest.raises(NoValue):
            provider(Request(name="test"))


class TestGetCa:
    def test_success(self):
        param = Mock(TeleportConnectionParameter)
        param.ca = b"-----MOCK CERTIFICATE-----"
        param.path_ca = Path("path/to/ca")

        assert get_ca(param, "path") == "path/to/ca"
        assert get_ca(param, "pem") == "-----MOCK CERTIFICATE-----"

    def test_fail(self):
        param = Mock(TeleportConnectionParameter)
        param.ca = None

        with pytest.raises(LookupError, match="CA is not available"):
            get_ca(param, "pem")
