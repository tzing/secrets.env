import datetime
import json
import logging
import re
import shutil
from pathlib import Path
from unittest.mock import Mock, patch

import cryptography.x509
import pytest

import secrets_env.providers.teleport.helper as t
from secrets_env.exceptions import (
    AuthenticationError,
    SecretsEnvError,
    UnsupportedError,
)
from secrets_env.providers.teleport.config import TeleportUserConfig
from secrets_env.providers.teleport.helper import (
    TeleportAppConfig,
    TeleportConnectionParameter,
    call_app_config,
    call_version,
    get_connection_param,
    try_get_app_config,
)
from secrets_env.subprocess import Run

no_teleport_cli = shutil.which("tsh") is None


@pytest.fixture()
def dummy_param():
    return TeleportConnectionParameter(
        uri="https://example.com", ca=b"ca", cert=b"cert", key=b"key"
    )


class TestTeleportAppConfig:
    def test_1(self, tmp_path: Path):
        text = json.dumps(
            {
                "uri": "https://example.com",
                "ca": str(tmp_path / "ca.crt"),
                "cert": str(tmp_path / "cert.crt"),
                "key": str(tmp_path / "key.key"),
            }
        )
        assert TeleportAppConfig.model_validate_json(text) == TeleportAppConfig(
            uri="https://example.com",
            ca=tmp_path / "ca.crt",
            cert=tmp_path / "cert.crt",
            key=tmp_path / "key.key",
        )

    def test_2(self, tmp_path: Path):
        text = json.dumps(
            {
                "uri": "https://example.com",
                "ca": None,
                "cert": str(tmp_path / "cert.crt"),
                "key": str(tmp_path / "key.key"),
            }
        )
        assert TeleportAppConfig.model_validate_json(text) == TeleportAppConfig(
            uri="https://example.com",
            ca=None,
            cert=tmp_path / "cert.crt",
            key=tmp_path / "key.key",
        )


class TestTeleportConnectionParameter:
    def test_model_validate(self, tmp_path: Path):
        (tmp_path / "cert.crt").write_bytes(b"cert")
        (tmp_path / "key.key").write_bytes(b"key")

        config = TeleportAppConfig(
            uri="https://example.com",
            ca=tmp_path / "ca.crt",
            cert=tmp_path / "cert.crt",
            key=tmp_path / "key.key",
        )

        parsed = TeleportConnectionParameter.model_validate(config)
        assert isinstance(parsed, TeleportConnectionParameter)
        assert parsed.uri == "https://example.com"
        assert parsed.ca is None
        assert parsed.cert == b"cert"
        assert parsed.key == b"key"

    def test_path(self, dummy_param: TeleportConnectionParameter):
        assert dummy_param.path_ca.is_file()
        assert dummy_param.path_ca.read_bytes() == b"ca"
        assert dummy_param.path_cert.is_file()
        assert dummy_param.path_cert.read_bytes() == b"cert"
        assert dummy_param.path_key.is_file()
        assert dummy_param.path_key.read_bytes() == b"key"
        assert dummy_param.path_cert_and_key.is_file()
        assert dummy_param.path_cert_and_key.read_bytes() == b"cert\nkey"

    def test_path_2(self):
        param = TeleportConnectionParameter(
            uri="https://example.com", ca=None, cert=b"cert", key=b"key"
        )
        assert param.path_ca is None

    def test_valid_cert(self, monkeypatch: pytest.MonkeyPatch):
        mock_cert = Mock(spec=cryptography.x509.Certificate)
        later = datetime.datetime.now().astimezone() + datetime.timedelta(days=30)
        mock_cert.not_valid_after_utc = later
        monkeypatch.setattr(
            "cryptography.x509.load_pem_x509_certificate", lambda _: mock_cert
        )

        cfg = TeleportConnectionParameter(
            uri="https://example.com", ca=None, cert=b"cert", key=b"key"
        )
        assert cfg.is_cert_valid() is True

    def test_expired_cert(self):
        cfg = TeleportConnectionParameter(
            uri="https://example.com", ca=None, cert=fake_cert, key=b"key"
        )
        assert cfg.is_cert_valid() is False


class TestGetConnectionParam:
    @pytest.fixture()
    def _patch_which(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr("shutil.which", lambda _: "/path/cmd")

    @pytest.fixture()
    def _patch_version(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(t, "call_version", lambda: True)

    @pytest.fixture()
    def _patch_call_app_login(self, monkeypatch: pytest.MonkeyPatch):
        def mock_call_app_login(params): ...

        monkeypatch.setattr(t, "call_app_login", mock_call_app_login)

    @pytest.mark.usefixtures(
        "_patch_which",
        "_patch_version",
        "_patch_call_app_login",
    )
    def test_success(
        self, monkeypatch: pytest.MonkeyPatch, dummy_param: TeleportConnectionParameter
    ):
        monkeypatch.setattr(t, "try_get_app_config", lambda _: None)
        monkeypatch.setattr(t, "call_app_config", lambda _: dummy_param)

        cfg = TeleportUserConfig(app="test")
        assert get_connection_param(cfg) == TeleportConnectionParameter(
            uri="https://example.com",
            ca=b"ca",
            cert=b"cert",
            key=b"key",
        )

    def test_missing_dependency(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr("shutil.which", lambda _: None)
        with pytest.raises(UnsupportedError):
            get_connection_param(TeleportUserConfig(app="test"))

    @pytest.mark.usefixtures("_patch_which")
    def test_internal_error(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(t, "call_version", lambda: False)
        with pytest.raises(SecretsEnvError):
            get_connection_param(TeleportUserConfig(app="test"))

    @pytest.mark.usefixtures("_patch_which", "_patch_version", "_patch_call_app_login")
    def test_no_config(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(t, "call_app_config", lambda _: None)
        with pytest.raises(AuthenticationError):
            get_connection_param(TeleportUserConfig(app="test"))


class TestTryGetAppConfig:
    def test_success(
        self, monkeypatch: pytest.MonkeyPatch, dummy_param: TeleportConnectionParameter
    ):
        monkeypatch.setattr(t, "call_app_config", lambda _: dummy_param)
        monkeypatch.setattr(
            t.TeleportConnectionParameter, "is_cert_valid", lambda _: True
        )
        assert try_get_app_config("test") == dummy_param

    def test_missing_dependency(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr("importlib.util.find_spec", lambda _: False)
        assert try_get_app_config("test") is None

    def test_no_config(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(t, "call_app_config", lambda _: None)
        assert try_get_app_config("test") is None

    def test_not_valid(
        self, monkeypatch: pytest.MonkeyPatch, dummy_param: TeleportConnectionParameter
    ):
        monkeypatch.setattr(t, "call_app_config", lambda _: dummy_param)
        monkeypatch.setattr(
            t.TeleportConnectionParameter, "is_cert_valid", lambda _: False
        )
        assert try_get_app_config("test") is None


fake_cert = b"""
-----BEGIN CERTIFICATE-----
MIIFazCCA1OgAwIBAgIUYBwyBPJrpNsQO3FYEZ/L5+egiAEwDQYJKoZIhvcNAQEL
BQAwRTELMAkGA1UEBhMCVFcxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yMzAxMDEwMDAwMDVaFw0yMzAx
MzEwMDAwMDVaMEUxCzAJBgNVBAYTAlRXMRMwEQYDVQQIDApTb21lLVN0YXRlMSEw
HwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggIiMA0GCSqGSIb3DQEB
AQUAA4ICDwAwggIKAoICAQDPkHAPnUCu5BR4WmKuojmUw8XOri3+T4K9pq0XzCqn
S/FXVZ3mw5PGzr4y56CfRbVzSQuCCgvVf2LWnyHxSriYf2NjZEH5KTyiJW4D1roS
sjdJ2kuBKMlzEl5MWhjeGeHN2UiC8DCr4k4od4oEuOAQE48THSwy0qILMMpVYTYK
SbLssXZv5PhXf7uwGRZ7ne5iN37Iy6j245pP7ctn1Sm5m/Rkq7VrH7KLpz/kbET2
A4qR7yxybsYMk4W2kL8MUxsESu6JgyjT9MMmyZBos7z6ncAbb0Hd3qltsie5s9xz
5GJ2m9yKollAfgMljSFEL15Qj3diC34Es8d9D3OtnvmKAXPAzp9PUDYqcMQvWh2V
6aNaAaCZaHpFyxFWVR1Bs914ZWdpx1vmqggqTjwF3OdKEwK4IvUTrNEA9gtIF7Rm
H9qQVV88JeWebps49/NmtnE5kuohoD6vs4q7zHGoTDoZPkFj+q+JxvlltxkYHtGe
oYnL0xjjG0ZRedn3aNyc7RBaA+GOxCZtNIzoCkyby/vYjfWa63G4rfSSG22j2Vco
2umyaeR9KO+R5Q4ywl9ivwhVG+L5Tk2AFuXLE5Rrw0IxE92CalHCWQMHk3wDahPO
WGkJn7NxNva/Upvrad/czr49RodQob0nd0uB5P/rz/Sab/zb+pAz/k57j5xp1/V7
4wIDAQABo1MwUTAdBgNVHQ4EFgQUG5X+y+js8mtNnvc51RghvQ2iW5cwHwYDVR0j
BBgwFoAUG5X+y+js8mtNnvc51RghvQ2iW5cwDwYDVR0TAQH/BAUwAwEB/zANBgkq
hkiG9w0BAQsFAAOCAgEACX5j2DDcPVxn2JEnxpkOC3iz/Vojlg0m+hDeGHMDms+S
m5sJhknDMkxfPUVbOFBmQJg2/FywEOnMkFLtYW8JJro+mUEAlLKtrzF0jw3+/ltQ
R/NUIFsVbEhFP/GI4x4YrJDrNHhSYNQPsUVwQsPHaZzeGGYPRqRN1gW0kbAgtTJO
A+VHoOOd9aNBXhY6hKQcyXPsNPSAtO7u5nlQyax5ef1pw82CYU2RBa6QIcXVjccq
FdTGhtZrP3/5POq3YPZuPSU8NbVksvHmWtN1K3fu1x14EO/nCanjMfCjouoUtbzm
H+TIKD66Kh6TuCSj4qxUoJ8b24C4Vf1+vurboEPA1Pz0ZG8ujfMyYqTHYeJcsUeO
3TfzaZWAK/EEMiM030L5h+OnzvSqJe/OtwpqfprKGA7D+44i4hTBuSLcq5Sj+woc
aA2WS5I923iHt+PWz+bXJenvc2b3nD3/Ghcz+cpJVYAZ30tOMtaoaDFD0hPYKa4S
xfcpHq56x/DQR3dC2QpK0TKLKRUOKiJID1UitL9pjSE0M2E4ImqPGJvDnAHabfag
x3oC0C1IeJyBpeNeI8cS9UUtcvaMWcdwxv4ISqTQdM0fNPKpmuVUBEq5oSAmSOdu
dlJU64TVUXlETsMiwhRLRSo7W5PJnxLnMFbsKaHyTBH/ioBEuF0GRpO93medyTA=
-----END CERTIFICATE-----
"""
