import logging
import os
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
    read_configmap,
    read_kv_pairs,
    read_secret,
)
from secrets_env.providers.kubernetes.models import Kind


@pytest.fixture
def _require_kubectl():
    if shutil.which("kubectl") is None:
        pytest.skip("kubectl is not installed")


@pytest.fixture
def intl_provider() -> KubectlProvider:
    if "K8S_CLUSTER" not in os.environ:
        pytest.skip("Test Kubernetes cluster is not set")
    return KubectlProvider()


class TestKubectlProvider:
    @pytest.fixture
    def _patch_kubectl_path(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr("shutil.which", Mock(return_value="/usr/bin/kubectl"))
        monkeypatch.setattr("pathlib.Path.is_file", Mock(return_value=True))

    @pytest.fixture
    def _patch_call_version(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(
            "secrets_env.providers.kubernetes.kubectl.call_version", Mock()
        )

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

    @pytest.mark.usefixtures("_patch_kubectl_path", "_patch_call_version")
    def test__get_kv_pairs_(self, monkeypatch: pytest.MonkeyPatch):
        # setup mock functions
        def _mock_read_secret(*, kubectl, config, context, namespace, name):
            assert namespace == "default"
            assert name == "test"
            return {"key": b"bar"}

        mock_read_secret = Mock(side_effect=_mock_read_secret)
        monkeypatch.setattr(
            "secrets_env.providers.kubernetes.kubectl.read_secret", mock_read_secret
        )

        def _mock_read_configmap(*, kubectl, config, context, namespace, name):
            assert namespace == "default"
            assert name == "test"
            return {"key": b"qux"}

        monkeypatch.setattr(
            "secrets_env.providers.kubernetes.kubectl.read_configmap",
            _mock_read_configmap,
        )

        # run
        provider = KubectlProvider()

        assert provider._get_kv_pairs_(Kind.Secret, "default", "test") == {
            "key": b"bar"
        }
        assert provider._get_kv_pairs_(Kind.Secret, "default", "test") == {
            "key": b"bar"
        }

        assert provider._get_kv_pairs_(Kind.ConfigMap, "default", "test") == {
            "key": b"qux"
        }

        # assert calls; the second call should be cached
        assert mock_read_secret.call_count == 1

    @pytest.mark.usefixtures("_patch_kubectl_path", "_patch_call_version")
    def test__get_kv_pairs_notfound(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(
            "secrets_env.providers.kubernetes.kubectl.read_secret",
            Mock(return_value=Marker.NotFound),
        )

        provider = KubectlProvider()
        with pytest.raises(LookupError):
            provider._get_kv_pairs_(Kind.Secret, "default", "test")

    def test__get_kv_pairs_unsupported(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr("shutil.which", Mock(return_value=None))

        provider = KubectlProvider()
        assert isinstance(provider, KubectlProvider)

        with pytest.raises(UnsupportedError):
            provider._get_kv_pairs_(Mock(Kind), "default", "test")

    @pytest.mark.usefixtures("_patch_kubectl_path")
    def test__get_value_(self, monkeypatch: pytest.MonkeyPatch):
        def _mock_get_secret(kind: Kind, namespace: str, name: str):
            assert kind == Kind.Secret
            assert namespace == "default"
            assert name == "test"
            return {"foo": b"bar"}

        provider = KubectlProvider()
        monkeypatch.setattr(provider, "_get_kv_pairs_", _mock_get_secret)

        request = Request(name="test", ref="default/test", key="foo")
        assert provider._get_value_(request) == "bar"

        request = Request(name="test", ref="default/test", key="no-this-key")
        with pytest.raises(LookupError):
            provider._get_value_(request)

    @pytest.mark.parametrize(
        ("requesting", "expected"),
        [
            (Request(name="test", ref="default/demo-secret", key="username"), "admin"),
            (Request(name="test", value="default/demo-secret#password"), "P@ssw0rd"),
            (
                Request(
                    name="test",
                    kind="configmap",
                    ref="default/demo-config",
                    key="host",
                ),
                "localhost",
            ),
        ],
    )
    def test_integration(
        self, intl_provider: KubectlProvider, requesting: Request, expected: str
    ):
        assert intl_provider(requesting) == expected


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


class TestReadKvPairs:
    def test_unknown(self):
        with pytest.raises(RuntimeError):
            read_kv_pairs(
                kubectl=Path("/usr/bin/kubectl"),
                config=None,
                context=None,
                kind=Mock(Kind),
                namespace="default",
                name="test",
            )


class TestReadSecret:
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
            name="demo-secret",
        )

        assert result == {"key": b"bar"}
        mock_check_output.assert_called_once_with(
            [
                "/usr/bin/kubectl",
                "get",
                "--kubeconfig",
                "/root/.kube/config",
                "--context",
                "minikube",
                "--namespace",
                "default",
                "secret",
                "demo-secret",
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
            name="demo-secret",
        )

        assert result == {"key": b"bar"}
        mock_check_output.assert_called_once_with(
            [
                "/usr/bin/kubectl",
                "get",
                "--namespace",
                "default",
                "secret",
                "demo-secret",
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


class TestReadConfigMap:
    @pytest.fixture
    def mock_check_output(self, monkeypatch: pytest.MonkeyPatch):
        mock = Mock(
            return_value="""
            {
                "apiVersion": "v1",
                "kind": "ConfigMap",
                "data": {
                    "key": "bar"
                }
            }
            """
        )
        monkeypatch.setattr(
            "secrets_env.providers.kubernetes.kubectl.check_output", mock
        )
        return mock

    def test_1(self, mock_check_output: Mock):
        result = read_configmap(
            kubectl=Path("/usr/bin/kubectl"),
            config=Path("/root/.kube/config"),
            context="minikube",
            namespace="default",
            name="demo-config",
        )

        assert result == {"key": b"bar"}
        mock_check_output.assert_called_once_with(
            [
                "/usr/bin/kubectl",
                "get",
                "--kubeconfig",
                "/root/.kube/config",
                "--context",
                "minikube",
                "--namespace",
                "default",
                "configmap",
                "demo-config",
                "--output",
                "json",
            ],
            level_error=logging.DEBUG,
        )

    def test_2(self, mock_check_output: Mock):
        result = read_configmap(
            kubectl=Path("/usr/bin/kubectl"),
            config=None,
            context=None,
            namespace="default",
            name="demo-config",
        )

        assert result == {"key": b"bar"}
        mock_check_output.assert_called_once_with(
            [
                "/usr/bin/kubectl",
                "get",
                "--namespace",
                "default",
                "configmap",
                "demo-config",
                "--output",
                "json",
            ],
            level_error=logging.DEBUG,
        )

    def test_not_found(self, mock_check_output):
        mock_check_output.side_effect = subprocess.CalledProcessError(1, "kubectl")

        result = read_configmap(
            kubectl=Path("/usr/bin/kubectl"),
            config=None,
            context=None,
            namespace="default",
            name="configmap",
        )
        assert result == Marker.NotFound
