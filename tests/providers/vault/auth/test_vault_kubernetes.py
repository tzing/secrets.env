from unittest.mock import Mock, mock_open

import pytest
from pydantic_core import Url

from secrets_env.exceptions import AuthenticationError
from secrets_env.providers.vault.auth.kubernetes import KubernetesAuth


class TestKubernetesAuth:
    @pytest.fixture()
    def _patch_open(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr("builtins.open", mock_open(read_data="t0ken"))

    @pytest.mark.usefixtures("_patch_open")
    def test_create__default(self):
        auth = KubernetesAuth.create(Url("http://vault:8200"), {})
        assert auth == KubernetesAuth(token="t0ken", role=None)

    @pytest.mark.usefixtures("_patch_open")
    def test_create__role_from_env(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("SECRETS_ENV_ROLE", "env-role")
        auth = KubernetesAuth.create(Url("http://vault:8200"), {"role": "cfg-role"})
        assert auth == KubernetesAuth(token="t0ken", role="env-role")

    @pytest.mark.usefixtures("_patch_open")
    def test_create__role_from_config(self):
        auth = KubernetesAuth.create(Url("http://vault:8200"), {"role": "cfg-role"})
        assert auth == KubernetesAuth(token="t0ken", role="cfg-role")

    def test_create__role_missing(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr("builtins.open", Mock(side_effect=FileNotFoundError))

        with pytest.raises(
            AuthenticationError, match="Kubernetes service account token not found"
        ):
            KubernetesAuth.create(Url("http://vault:8200"), {})
