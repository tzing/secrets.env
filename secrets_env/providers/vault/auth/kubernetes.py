from __future__ import annotations

import logging
import typing

from pydantic import SecretStr

from secrets_env.exceptions import AuthenticationError
from secrets_env.providers.vault.auth.jwt import JwtAuth

if typing.TYPE_CHECKING:
    from pydantic_core import Url
    from typing_extensions import Self

logger = logging.getLogger(__name__)


class KubernetesAuth(JwtAuth):
    """
    Authenticate with Kubernetes service account token.
    """

    request_path = "/v1/auth/kubernetes/login"

    @classmethod
    def create(cls, url: Url, config: dict) -> Self:
        # get token
        try:
            with open("/var/run/secrets/kubernetes.io/serviceaccount/token") as fd:
                token = typing.cast(SecretStr, fd.read())
        except FileNotFoundError as e:
            raise AuthenticationError(
                "Kubernetes service account token not found"
            ) from e

        # get role
        role = config.get("role")

        return cls(token=token, role=role)
