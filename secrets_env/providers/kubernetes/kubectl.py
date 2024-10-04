from __future__ import annotations

import base64
import enum
import functools
import logging
import shutil
import subprocess
import typing

from pydantic import Field, FilePath, PrivateAttr, model_validator

from secrets_env.exceptions import UnsupportedError
from secrets_env.provider import Provider
from secrets_env.providers.kubernetes.models import (
    ConfigMapV1,
    Kind,
    KubeRequest,
    SecretV1,
)
from secrets_env.realms.subprocess import check_output
from secrets_env.utils import LruDict, get_env_var

if typing.TYPE_CHECKING:
    from pathlib import Path
    from typing import Literal

    from secrets_env.provider import Request

    _T_Data = dict[str, bytes]

logger = logging.getLogger(__name__)


class Marker(enum.Enum):
    """Internal marker for cache handling."""

    NoCache = enum.auto()
    NotFound = enum.auto()


class KubectlProvider(Provider):
    """
    Read secrets from Kubernetes secrets using kubectl.
    """

    type = "kubectl"

    kubectl: FilePath | None = Field(
        default_factory=lambda: shutil.which("kubectl"),
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

    _cache: dict[tuple[Kind, str, str], _T_Data | Marker] = PrivateAttr(
        default_factory=LruDict
    )

    @model_validator(mode="before")
    @classmethod
    def _use_env_var(cls, values):
        if isinstance(values, dict):
            if path := get_env_var("KUBECONFIG"):
                values["config"] = path
        return values

    def _get_kv_pairs_(self, kind: Kind, namespace: str, name: str) -> _T_Data:
        if not self.kubectl:
            raise UnsupportedError("kubectl command is not installed or accessible")

        call_version(self.kubectl)  # leave a sign in the log

        result = self._cache.get((kind, namespace, name), Marker.NoCache)

        if result is Marker.NoCache:
            result = read_kv_pairs(
                kubectl=self.kubectl,
                config=self.config,
                context=self.context,
                kind=kind,
                namespace=namespace,
                name=name,
            )
            self._cache[kind, namespace, name] = result

        if result is Marker.NotFound:
            raise LookupError(f'Failed to read {kind.name} "{name}" from kubectl')

        return result

    def _get_value_(self, spec: Request) -> str:
        request = KubeRequest.model_validate(spec.model_dump(exclude_none=True))

        secret = self._get_kv_pairs_(request.kind, request.namespace, request.name)
        if request.key not in secret:
            raise LookupError(
                f'Key "{request.key}" not found in secret "{request.name}"'
            )

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
) -> _T_Data | Literal[Marker.NotFound]:
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
) -> _T_Data | Literal[Marker.NotFound]:
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
        return Marker.NotFound

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
) -> _T_Data | Literal[Marker.NotFound]:
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
        return Marker.NotFound

    configmap = ConfigMapV1.model_validate_json(output)

    # encode values; for alignment with secrets
    output = {}
    for key, value in configmap.data.items():
        output[key] = value.encode()

    return output
