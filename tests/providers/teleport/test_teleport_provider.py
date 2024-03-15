from pathlib import Path
from unittest.mock import Mock

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
