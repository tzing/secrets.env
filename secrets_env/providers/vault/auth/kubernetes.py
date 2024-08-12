from __future__ import annotations

import logging
import typing

from pydantic import SecretStr

from secrets_env.providers.vault.auth.jwt import JwtAuth
from secrets_env.utils import get_env_var

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
        with open("/var/run/secrets/kubernetes.io/serviceaccount/token") as fd:
            token = typing.cast(SecretStr, fd.read())

        # get role
        if role := get_env_var("SECRETS_ENV_ROLE"):
            logger.debug("Found Kubernetes role from environment variable: %s", role)
        elif role := config.get("role"):
            logger.debug("Found Kubernetes role from config file: %s", role)
        else:
            logger.debug("Missing Kubernetes role. Use default.")
            role = None

        return cls(token=token, role=role)
