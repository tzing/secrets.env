from __future__ import annotations

import base64
import functools
import logging
import shutil
import subprocess
import typing

from pydantic import Field, FilePath, model_validator

from secrets_env.exceptions import UnsupportedError
from secrets_env.provider import Provider
from secrets_env.providers.kubernetes.models import (
    ConfigMapV1,
    Kind,
    KubeRequest,
    SecretV1,
)
from secrets_env.realms.subprocess import check_output
from secrets_env.utils import cache_query_result, get_env_var

if typing.TYPE_CHECKING:
    from pathlib import Path

    from secrets_env.provider import Request

    _T_Data = dict[str, bytes]

logger = logging.getLogger(__name__)


class KubectlProvider(Provider):
    """
    Read secrets from Kubernetes secrets using kubectl.
    """

    type = "kubectl"

    path: FilePath | None = Field(
        default_factory=lambda: typing.cast("FilePath", shutil.which("kubectl")),
        validate_default=True,
    )
    """
    Path to the kubectl binary. If not set, the provider will try to find it in the PATH.
    """

    config: FilePath | None = None
    """
    Path to the kubeconfig file. If not set, the default kubeconfig will be used.
    """

    context: str | None = None
    """
    The Kubernetes context to use. If not set, the current context will be used.
    """

    @model_validator(mode="before")
    @classmethod
    def _use_env_var(cls, values):
        if isinstance(values, dict):
            if path := get_env_var("KUBECONFIG"):
                values["config"] = path
        return values

    @cache_query_result()
    def _get_kv_pairs_(self, kind: Kind, namespace: str, name: str) -> _T_Data:
        if not self.path:
            raise UnsupportedError("kubectl command is not installed or accessible")

        call_version(self.path)  # leave a sign in the log

        return read_kv_pairs(
            kubectl=self.path,
            config=self.config,
            context=self.context,
            kind=kind,
            namespace=namespace,
            name=name,
        )

    @cache_query_result()
    def _get_value_(self, spec: Request) -> str:
        request = KubeRequest.model_validate(spec.model_dump(exclude_none=True))

        secret = self._get_kv_pairs_(request.kind, request.namespace, request.name)
        if request.key not in secret:
            raise LookupError(
                f'Key "{request.key}" not found in secret "{request.name}"'
            ) from None

        return secret[request.key].decode()


@functools.lru_cache(1)
def call_version(kubectl: Path) -> None:
    """Call version command and print it to log."""
    try:
        check_output([str(kubectl), "version", "--client"])
    except subprocess.CalledProcessError:
        raise RuntimeError("Internal error on invoking kubectl") from None


def read_kv_pairs(
    *,
    kubectl: Path,
    config: Path | None,
    context: str | None,
    kind: Kind,
    namespace: str,
    name: str,
) -> _T_Data:
    if kind == Kind.Secret:
        return read_secret(
            kubectl=kubectl,
            config=config,
            context=context,
            namespace=namespace,
            name=name,
        )

    if kind == Kind.ConfigMap:
        return read_configmap(
            kubectl=kubectl,
            config=config,
            context=context,
            namespace=namespace,
            name=name,
        )

    raise RuntimeError(f"Unsupported kind: {kind}")


def read_secret(
    *,
    kubectl: Path,
    config: Path | None,
    context: str | None,
    namespace: str,
    name: str,
) -> _T_Data:
    """Request a secret from Kubernetes using kubectl."""
    # build command
    cmd = [str(kubectl), "get"]
    if config:
        cmd += ["--kubeconfig", str(config)]
    if context:
        cmd += ["--context", context]

    cmd += ["--namespace", namespace, "secret", name, "--output", "json"]

    # get secret
    try:
        output = check_output(
            cmd,
            level_output=None,
            level_error=logging.DEBUG,
        )
    except subprocess.CalledProcessError:
        raise LookupError(f'Failed to read secret "{name}" from kubectl') from None

    secret = SecretV1.model_validate_json(output)

    # decode base64 values
    output = {}
    for key, value in secret.data.items():
        output[key] = base64.b64decode(value)

    return output


def read_configmap(
    *,
    kubectl: Path,
    config: Path | None,
    context: str | None,
    namespace: str,
    name: str,
) -> _T_Data:
    """Request a value from Kubernetes using kubectl."""
    # build command
    cmd = [str(kubectl), "get"]
    if config:
        cmd += ["--kubeconfig", str(config)]
    if context:
        cmd += ["--context", context]

    cmd += ["--namespace", namespace, "configmap", name, "--output", "json"]

    # get secret
    try:
        output = check_output(
            cmd,
            level_error=logging.DEBUG,
        )
    except subprocess.CalledProcessError:
        raise LookupError(f'Failed to read configmap "{name}" from kubectl') from None

    configmap = ConfigMapV1.model_validate_json(output)

    # encode values; for alignment with secrets
    output = {}
    for key, value in configmap.data.items():
        output[key] = value.encode()

    return output
