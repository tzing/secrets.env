import pytest
from pydantic import ValidationError

from secrets_env.providers.kubernetes.models import Kind, KubeRequest


class TestKubeRequest:

    def test_standard(self):
        request = KubeRequest.model_validate(
            {
                "ref": "namespace/secret-name",
                "key": "key",
                "kind": "configmap",
            }
        )
        assert isinstance(request, KubeRequest)
        assert request.ref == "namespace/secret-name"
        assert request.key == "key"
        assert request.kind == Kind.ConfigMap
        assert request.namespace == "namespace"
        assert request.name == "secret-name"

    def test_shortcut(self):
        request = KubeRequest.model_validate(
            {
                "value": "namespace/secret-name#foo.bar_baz",
            }
        )
        assert isinstance(request, KubeRequest)
        assert request.ref == "namespace/secret-name"
        assert request.key == "foo.bar_baz"
        assert request.kind == Kind.Secret

    def test_invalid_names(self):
        with pytest.raises(ValidationError):
            KubeRequest.model_validate(
                {
                    "ref": "invalid_namespace/secret-name",
                    "key": "key",
                }
            )

        with pytest.raises(ValidationError):
            KubeRequest.model_validate(
                {
                    "ref": "namespace/secret_name",
                    "key": "key",
                }
            )

        with pytest.raises(ValidationError):
            KubeRequest.model_validate(
                {
                    "ref": "namespace/secret-name",
                    "key": "invalid@key",
                }
            )
