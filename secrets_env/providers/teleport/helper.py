"""An helper module that wraps `Teleport CLI`_ (``tsh``) and get connection
information from it.

.. _Teleport CLI: https://goteleport.com/docs/reference/cli/
"""

from __future__ import annotations

import atexit
import datetime
import importlib.util
import logging
import os
import shutil
import tempfile
import typing
from functools import cached_property
from pathlib import Path
from typing import Annotated

from pydantic import BaseModel, BeforeValidator, model_validator

from secrets_env.exceptions import (
    AuthenticationError,
    SecretsEnvError,
    UnsupportedError,
)
from secrets_env.subprocess import Run

if typing.TYPE_CHECKING:
    from secrets_env.providers.teleport.config import TeleportUserConfig


TELEPORT_APP_NAME = "tsh"

logger = logging.getLogger(__name__)


class TeleportAppConfig(BaseModel):
    """Layout returned by `tsh app config` command."""

    uri: str
    """URI to the app."""

    ca: Path | None
    """Certificate authority (CA) certificate."""

    cert: Path
    """Client side certificate."""

    key: Path
    """Client side private key."""


def _path_validator(data):
    if isinstance(data, Path):
        if data.is_file():
            return data.read_bytes()
        else:
            return None
    return data


class TeleportConnectionParameter(BaseModel):
    """App URI and the short-lived certificate for Teleport.

    This object copied the certificate on object creation, and destroy them
    when secrets.env terminated.
    """

    uri: str
    """URI to the app."""

    ca: Annotated[bytes | None, BeforeValidator(_path_validator)]
    """Certificate authority (CA) certificate."""

    cert: Annotated[bytes, BeforeValidator(_path_validator)]
    """Client side certificate."""

    key: Annotated[bytes, BeforeValidator(_path_validator)]
    """Client side private key."""

    @model_validator(mode="before")
    def _from_teleport_app_config(cls, values):
        if isinstance(values, TeleportAppConfig):
            return values.model_dump()
        return values

    @cached_property
    def cert_and_key(self) -> bytes:
        return self.cert + b"\n" + self.key

    @cached_property
    def path_ca(self) -> Path | None:
        if not self.ca:
            return None
        return _create_temp_file(".crt", self.ca)

    @cached_property
    def path_cert(self) -> Path:
        return _create_temp_file(".cert", self.cert)

    @cached_property
    def path_key(self) -> Path:
        return _create_temp_file(".key", self.key)

    @cached_property
    def path_cert_and_key(self) -> Path:
        return _create_temp_file(".pem", self.cert_and_key)

    def is_cert_valid(self) -> bool:
        """Check if the certificate is still valid.

        Raises
        ------
        ImportError
            When `cryptography` package is not installed.
        """
        import cryptography.x509

        cert = cryptography.x509.load_pem_x509_certificate(self.cert)
        now = datetime.datetime.now().astimezone()
        if now > cert.not_valid_after_utc:
            logger.debug(
                "Certificate expire at %s < current time %s",
                cert.not_valid_after_utc.astimezone(),
                now,
            )
            return False

        return True


def _create_temp_file(suffix: str, data: bytes) -> Path:
    fd, path = tempfile.mkstemp(suffix=suffix)

    os.write(fd, data)
    os.close(fd)

    atexit.register(os.remove, path)

    return Path(path)


def get_connection_param(config: TeleportUserConfig) -> TeleportConnectionParameter:
    """Get app connection parameter from Teleport CLI.

    Raises
    ------
    AuthenticationError
        Failed to login to Teleport.
    UnsupportedError
        When Teleport CLI not installed.
    """
    # ensure teleport cli is installed
    if not shutil.which(TELEPORT_APP_NAME):
        raise UnsupportedError(
            f"Teleport CLI ({TELEPORT_APP_NAME}) is required for teleport addon"
        )

    # it might take a while for teleport RPC. show the message to indicate that
    # the script is not freeze
    logger.info(
        "<!important>Get connection information from Teleport for %s", config.app
    )
    logger.debug("Teleport app parameters= %s", config)

    # log version before start
    if not call_version():
        raise SecretsEnvError("Internal error on accessing Teleport CLI")

    # try to get config directly; when not available, loging and retry
    param = try_get_app_config(config.app)

    if not param:
        call_app_login(config)
        param = call_app_config(config.app)

    if not param:
        raise AuthenticationError("Failed to get connection info from Teleport")

    return param


def try_get_app_config(app: str) -> TeleportConnectionParameter | None:
    """The certificate refreshing process takes a while so we'd like to directly
    use the one stored on disk. Teleport sometimes responds the file path without
    expiration check. Therefore we need to check it by ourself.
    """
    # need cryptography package to read cert file
    if not importlib.util.find_spec("cryptography"):
        return

    logger.debug("Try to get config directly")
    param = call_app_config(app)
    if not param:
        # not login yet / teleport detect expired
        return

    if not param.is_cert_valid():
        # cert is expired
        return

    return param


def call_version() -> bool:
    """Call version command and print it to log."""
    runner = Run([TELEPORT_APP_NAME, "version"])
    runner.wait()
    return runner.return_code == 0


def call_app_config(app: str) -> TeleportConnectionParameter | None:
    runner = Run([TELEPORT_APP_NAME, "app", "config", "--format=json", app])
    if runner.return_code != 0:
        return

    config = TeleportAppConfig.model_validate_json(runner.stdout)
    return TeleportConnectionParameter.model_validate(config)


def call_app_login(config: TeleportUserConfig) -> None:
    """Call `tsh app login`. Only returns on success.

    Raises
    ------
    AuthenticationError
        Login failed
    """
    # build arguments
    cmd = [TELEPORT_APP_NAME, "app", "login"]
    if config.proxy:
        cmd.append(f"--proxy={config.proxy}")
    if config.cluster:
        cmd.append(f"--cluster={config.cluster}")
    if config.user:
        cmd.append(f"--user={config.user}")
    cmd.append(config.app)

    # run
    runner = Run(cmd)

    for line in runner.iter_any_output():
        # early escape on detect 'success' message from stdout
        if line.startswith("Logged into app"):
            break

        # capture auth url from stderr
        line = line.lstrip()
        if line.startswith("http://127.0.0.1:"):
            logger.info(
                "<!important>"
                "Waiting for response from Teleport...\n"
                "If browser does not open automatically, open the link:\n"
                f"  <link>{line}</link>"
            )

    runner.wait()

    if runner.return_code == 0:
        logger.info("Successfully logged into app %s", config.app)
        return None

    if f'app "{config.app}" not found' in runner.stderr:
        raise AuthenticationError(f"Teleport app '{config.app}' not found")

    raise AuthenticationError(f"Teleport error: {runner.stderr}")
