import logging
import shutil
import subprocess
from pathlib import Path
from unittest.mock import Mock

import pytest

from secrets_env.exceptions import UnsupportedError
from secrets_env.provider import Request
from secrets_env.providers.kubernetes.kubectl import (
    KubectlProvider,
    Marker,
    call_version,
    read_secret,
)


@pytest.fixture
def _require_kubectl():
    if shutil.which("kubectl") is None:
        pytest.skip("kubectl is not installed")


class TestKubectlProvider:
    @pytest.fixture
    def _patch_kubectl_path(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr("shutil.which", Mock(return_value="/usr/bin/kubectl"))
        monkeypatch.setattr("pathlib.Path.is_file", Mock(return_value=True))

    @pytest.mark.usefixtures("_patch_kubectl_path")
    def test___init__(self):
        provider = KubectlProvider.model_validate({})
        assert provider.kubectl == Path("/usr/bin/kubectl")
        assert provider.config is None

        provider = KubectlProvider.model_validate(
            {
                "kubectl": "/root/local/bin/kubectl",
                "config": "/root/.kube/config",
            }
        )
        assert provider.kubectl == Path("/root/local/bin/kubectl")
        assert provider.config == Path("/root/.kube/config")

    @pytest.mark.usefixtures("_patch_kubectl_path")
    def test___init__config(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("KUBECONFIG", "/etc/kubeconfig")

        provider = KubectlProvider.model_validate({})
        assert provider.config == Path("/etc/kubeconfig")

        provider = KubectlProvider.model_validate({"config": "/root/.kube/config"})
        assert provider.config == Path("/etc/kubeconfig")

    def test___init__without_kubectl(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr("shutil.which", Mock(return_value=None))

        provider = KubectlProvider.model_validate({})
        assert provider.kubectl is None
        assert provider.context is None

    @pytest.mark.usefixtures("_patch_kubectl_path")
    def test__get_secret_(self, monkeypatch: pytest.MonkeyPatch):
        def _mock_read_secret(*, kubectl, config, context, namespace, name):
            assert namespace == "default"
            assert name == "test"
            return {"key": b"bar"}

        mock_read_secret = Mock(side_effect=_mock_read_secret)
        monkeypatch.setattr(
            "secrets_env.providers.kubernetes.kubectl.read_secret", mock_read_secret
        )

        provider = KubectlProvider()
        assert provider._get_secret_("default", "test") == {"key": b"bar"}
        assert provider._get_secret_("default", "test") == {"key": b"bar"}

        assert mock_read_secret.call_count == 1

    @pytest.mark.usefixtures("_patch_kubectl_path")
    def test__get_secret_notfound(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(
            "secrets_env.providers.kubernetes.kubectl.read_secret",
            Mock(return_value=Marker.NotFound),
        )

        provider = KubectlProvider()
        with pytest.raises(LookupError):
            provider._get_secret_("default", "test")

    def test__get_secret_unsupported(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr("shutil.which", Mock(return_value=None))

        provider = KubectlProvider()
        assert isinstance(provider, KubectlProvider)

        with pytest.raises(UnsupportedError):
            provider._get_secret_("default", "test")

    @pytest.mark.usefixtures("_patch_kubectl_path")
    def test__get_value_(self, monkeypatch: pytest.MonkeyPatch):
        def _mock_get_secret(namespace: str, name: str):
            assert namespace == "default"
            assert name == "test"
            return {"foo": b"bar"}

        provider = KubectlProvider()
        monkeypatch.setattr(provider, "_get_secret_", _mock_get_secret)

        request = Request(name="test", ref="default/test", key="foo")
        assert provider._get_value_(request) == "bar"

        request = Request(name="test", ref="default/test", key="no-this-key")
        with pytest.raises(LookupError):
            provider._get_value_(request)


class TestCallVersion:
    @pytest.fixture(autouse=True)
    def _reset_cache(self):
        yield
        call_version.cache_clear()

    def test_success(self, monkeypatch: pytest.MonkeyPatch):
        mock_check_output = Mock(return_value=b"Client Version: v1.20.0")
        monkeypatch.setattr(
            "secrets_env.providers.kubernetes.kubectl.check_output", mock_check_output
        )

        call_version(Path("/usr/bin/kubectl"))

        mock_check_output.assert_called_once_with(
            ["/usr/bin/kubectl", "version", "--client"]
        )

    def test_fail(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(
            "secrets_env.providers.kubernetes.kubectl.check_output",
            Mock(side_effect=subprocess.CalledProcessError(1, "kubectl")),
        )

        with pytest.raises(RuntimeError):
            call_version(Path("/usr/bin/kubectl"))

    @pytest.mark.usefixtures("_require_kubectl")
    def test_integration(self, caplog: pytest.LogCaptureFixture):
        with caplog.at_level(logging.DEBUG):
            call_version(shutil.which("kubectl"))
        assert "Client Version:" in caplog.text


class TestReadSecret:
    @pytest.fixture(autouse=True)
    def _patch_read_secret(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(
            "secrets_env.providers.kubernetes.kubectl.call_version", Mock()
        )

    @pytest.fixture
    def mock_check_output(self, monkeypatch: pytest.MonkeyPatch):
        mock = Mock(
            return_value="""
            {
                "apiVersion": "v1",
                "kind": "Secret",
                "data": {
                    "key": "YmFy"
                }
            }
            """
        )
        monkeypatch.setattr(
            "secrets_env.providers.kubernetes.kubectl.check_output", mock
        )
        return mock

    def test_1(self, mock_check_output: Mock):
        result = read_secret(
            kubectl=Path("/usr/bin/kubectl"),
            config=Path("/root/.kube/config"),
            context="minikube",
            namespace="default",
            name="secret",
        )

        assert result == {"key": b"bar"}
        mock_check_output.assert_called_once_with(
            [
                "/usr/bin/kubectl",
                "get",
                "secret",
                "--kubeconfig",
                "/root/.kube/config",
                "--context",
                "minikube",
                "--namespace",
                "default",
                "secret",
                "--output",
                "json",
            ],
            level_output=None,
            level_error=logging.DEBUG,
        )

    def test_2(self, mock_check_output: Mock):
        result = read_secret(
            kubectl=Path("/usr/bin/kubectl"),
            config=None,
            context=None,
            namespace="default",
            name="secret",
        )

        assert result == {"key": b"bar"}
        mock_check_output.assert_called_once_with(
            [
                "/usr/bin/kubectl",
                "get",
                "secret",
                "--namespace",
                "default",
                "secret",
                "--output",
                "json",
            ],
            level_output=None,
            level_error=logging.DEBUG,
        )

    def test_not_found(self, mock_check_output):
        mock_check_output.side_effect = subprocess.CalledProcessError(1, "kubectl")

        result = read_secret(
            kubectl=Path("/usr/bin/kubectl"),
            config=None,
            context=None,
            namespace="default",
            name="secret",
        )
        assert result == Marker.NotFound
