from pathlib import Path
from unittest.mock import Mock, PropertyMock

import pytest

from secrets_env.providers.teleport.config import TeleportConnectionParameter
from secrets_env.providers.teleport.provider import (
    TeleportProvider,
    TeleportRequestSpec,
    get_ca,
)


class TestTeleportRequestSpec:
    def test_success(self):
        spec = TeleportRequestSpec.model_validate({"field": "ca", "format": "pem"})
        assert spec == TeleportRequestSpec(field="ca", format="pem")

    def test_shortcut(self):
        spec = TeleportRequestSpec.model_validate("uri")
        assert spec == TeleportRequestSpec(field="uri", format="path")


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
        assert provider.get("uri") == "https://example.com"

    def test_get_ca(self, provider: TeleportProvider):
        expect = "subject=/C=XX/L=Default City/O=Test\n-----MOCK CERTIFICATE-----"
        assert provider.get({"field": "ca", "format": "pem"}) == expect
        with open(provider.get("ca")) as fd:
            assert fd.read() == expect

    def test_get_cert(self, provider: TeleportProvider):
        expect = "-----MOCK CERTIFICATE-----"
        assert provider.get({"field": "cert", "format": "pem"}) == expect
        with open(provider.get("cert")) as fd:
            assert fd.read() == expect

    def test_get_key(self, provider: TeleportProvider):
        expect = "-----MOCK PRIVATE KEY-----"
        assert provider.get({"field": "key", "format": "pem"}) == expect
        with open(provider.get("key")) as fd:
            assert fd.read() == expect

    def test_get_cert_and_key(self, provider: TeleportProvider):
        expect = "-----MOCK CERTIFICATE-----\n-----MOCK PRIVATE KEY-----"
        assert provider.get({"field": "cert+key", "format": "pem"}) == expect
        with open(provider.get("cert+key")) as fd:
            assert fd.read() == expect


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
