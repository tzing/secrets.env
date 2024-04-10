from __future__ import annotations

import datetime
import importlib.util
import logging
import os
import shutil
from functools import cached_property
from pathlib import Path
from typing import Annotated

from pydantic import (
    AfterValidator,
    BaseModel,
    BeforeValidator,
    FilePath,
    model_validator,
)

from secrets_env.exceptions import AuthenticationError, UnsupportedError

TELEPORT_APP_NAME = "tsh"

logger = logging.getLogger(__name__)


class TeleportUserConfig(BaseModel):
    """Parameters for retrieving app certificates from Teleport."""

    proxy: str | None = None
    cluster: str | None = None
    user: str | None = None
    app: str

    @model_validator(mode="before")
    @classmethod
    def _use_shortcut(cls, data):
        if isinstance(data, str):
            return {"app": data}
        return data

    @cached_property
    def connection_param(self) -> TeleportConnectionParameter:
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
            f"<!important>Get connection information from Teleport for {self.app}"
        )
        logger.debug(f"Teleport app parameters= {self!r}")

        # log version before start
        if not call_version():
            raise RuntimeError("Internal error on accessing Teleport CLI")

        # try to get config directly; when not available, loging and retry
        param = try_get_app_config(self.app)

        if not param:
            call_app_login(self)
            param = call_app_config(self.app)

        if not param:
            raise AuthenticationError("Failed to get connection info from Teleport")

        return param


def _path_to_bytes(data):
    if isinstance(data, Path):
        return data.read_bytes()
    return data


def _create_temp_file(suffix: str, data: bytes) -> Path:
    import atexit
    import tempfile

    fd, path = tempfile.mkstemp(suffix=suffix)

    os.write(fd, data)
    os.close(fd)

    atexit.register(os.remove, path)

    return Path(path)


class TeleportConnectionParameter(BaseModel):
    """App URI and the short-lived certificate for Teleport.

    This object copied the certificate on object creation, and destroy them
    when secrets.env terminated.
    """

    uri: str
    """URI to the app."""

    ca: Annotated[bytes | None, BeforeValidator(_path_to_bytes)]
    """Certificate authority (CA) certificate."""

    cert: Annotated[bytes, BeforeValidator(_path_to_bytes)]
    """Client side certificate."""

    key: Annotated[bytes, BeforeValidator(_path_to_bytes)]
    """Client side private key."""

    @model_validator(mode="before")
    @classmethod
    def _from_tsh_app_config(cls, values):
        if isinstance(values, TshAppConfigResponse):
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
        """Check if the certificate is still valid now.

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
    import subprocess

    cmd = [TELEPORT_APP_NAME, "version"]
    logger.debug("$ %s", " ".join(cmd))

    try:
        stdout = subprocess.check_output(cmd, stderr=subprocess.PIPE, encoding="utf-8")
    except subprocess.CalledProcessError:
        return False

    logger.debug("<[stdout] %s", stdout)
    return True


def _drop_on_not_exist(path: Path | None) -> Path | None:
    if isinstance(path, Path):
        if not path.is_file():
            return None
    return path


class TshAppConfigResponse(BaseModel):
    """Layout returned by `tsh app config` command."""

    uri: str
    """URI to the app."""

    ca: Annotated[Path | None, AfterValidator(_drop_on_not_exist)]
    """Certificate authority (CA) certificate."""

    cert: FilePath
    """Client side certificate."""

    key: FilePath
    """Client side private key."""


def call_app_config(app: str) -> TeleportConnectionParameter | None:
    import subprocess

    cmd = [TELEPORT_APP_NAME, "app", "config", "--format=json", app]
    logger.debug("$ %s", " ".join(cmd))

    try:
        stdout = subprocess.check_output(cmd, stderr=subprocess.PIPE, encoding="utf-8")
    except subprocess.CalledProcessError:
        return

    config = TshAppConfigResponse.model_validate_json(stdout)
    return TeleportConnectionParameter.model_validate(config)


def call_app_login(config: TeleportUserConfig) -> None:
    """Call `tsh app login`. Only returns on success.

    Raises
    ------
    AuthenticationError
        Login failed
    """
    import io

    import pexpect

    # build arguments
    args = ["app", "login"]
    if config.proxy:
        args.append(f"--proxy={config.proxy}")
    if config.cluster:
        args.append(f"--cluster={config.cluster}")
    if config.user:
        args.append(f"--user={config.user}")
    args.append(config.app)

    logger.debug("$ %s %s", TELEPORT_APP_NAME, " ".join(args))

    # run
    with io.StringIO() as capture_stdout, io.StringIO() as capture_stderr:
        proc = pexpect.spawn(TELEPORT_APP_NAME, args, timeout=None, encoding="utf-8")
        proc.logfile = capture_stdout
        proc.stderr = capture_stderr

        while True:
            match = proc.expect(
                [
                    "Logged into app",
                    r"http://127\.0\.0\.1:\d+/[0-9a-f-]+",
                    f'app "{config.app}" not found',
                    pexpect.EOF,
                ]
            )

            if match in (0, 3):
                break

            elif match == 1:
                link = proc.match.group(0)
                logger.info(
                    "<!important>"
                    "Waiting for response from Teleport...\n"
                    "If browser does not open automatically, open the link:\n"
                    f"  <link>{link}</link>"
                )

            elif match == 2:
                raise AuthenticationError(f"Teleport app '{config.app}' not found")

        proc.close()

        logger.debug("< return code: %s", proc.exitstatus)
        for line in capture_stdout.getvalue().splitlines():
            logger.debug("<[stdout] %s", line)
        for line in capture_stderr.getvalue().splitlines():
            logger.debug("<[stderr] %s", line)

        if proc.exitstatus != 0:
            error = capture_stderr.getvalue().rstrip()
            raise AuthenticationError(f"Teleport error: {error}")

    logger.info("Successfully logged into app %s", config.app)
