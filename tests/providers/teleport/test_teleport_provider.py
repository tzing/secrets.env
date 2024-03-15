from secrets_env.providers.teleport.provider import (
    TeleportProvider,
    TeleportRequestSpec,
)


class TestTeleportRequestSpec:
    def test_success(self):
        spec = TeleportRequestSpec.model_validate({"field": "ca", "format": "pem"})
        assert spec == TeleportRequestSpec(field="ca", format="pem")

    def test_shortcut(self):
        spec = TeleportRequestSpec.model_validate("uri")
        assert spec == TeleportRequestSpec(field="uri", format="path")
