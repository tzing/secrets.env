import logging
import re
import shutil

import pytest

import secrets_env.teleport as t

no_teleport_cli = shutil.which("tsh") is None


@pytest.mark.skipif(no_teleport_cli, reason="Teleport CLI not installed")
def test_call_version(caplog: pytest.LogCaptureFixture):
    with caplog.at_level(logging.DEBUG):
        assert t.call_version() is True
    assert re.search(r"< Teleport v\d+\.\d+\.\d+", caplog.text)
