import datetime
import logging
import re
import shutil
import tempfile
from unittest.mock import Mock, mock_open, patch

import cryptography.x509
import pytest

import secrets_env.providers.teleport.helper as t
from secrets_env.exceptions import (
    AuthenticationError,
    SecretsEnvError,
    UnsupportedError,
)
from secrets_env.subprocess import Run

no_teleport_cli = shutil.which("tsh") is None


def test_app_connection_info():
    with tempfile.NamedTemporaryFile() as fd_ca, tempfile.NamedTemporaryFile() as fd_cert, tempfile.NamedTemporaryFile() as fd_key:
        fd_cert.write(b"cert")
        fd_cert.flush()
        fd_key.write(b"key")
        fd_key.flush()
        fd_ca.write(b"ca")
        fd_ca.flush()

        cfg = t.AppConnectionInfo.from_config(
            uri="https://example.com", ca=fd_ca.name, cert=fd_cert.name, key=fd_key.name
        )

    assert cfg == t.AppConnectionInfo(
        uri="https://example.com", ca=b"ca", cert=b"cert", key=b"key"
    )

    assert cfg.path_ca.is_file()
    assert cfg.path_ca.read_bytes() == b"ca"
    assert cfg.path_cert.is_file()
    assert cfg.path_cert.read_bytes() == b"cert"
    assert cfg.path_key.is_file()
    assert cfg.path_key.read_bytes() == b"key"
    assert cfg.path_cert_and_key.is_file()
    assert cfg.path_cert_and_key.read_bytes() == b"cert\nkey"


class TestGetConnectionInfo:
    @pytest.fixture()
    def _patch_which(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr("shutil.which", lambda _: "/path/cmd")

    @pytest.fixture()
    def _patch_version(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(t, "call_version", lambda: True)

    @pytest.fixture()
    def _patch_call_app_login(self, monkeypatch: pytest.MonkeyPatch):
        def mock_call_app_login(params):
            ...

        monkeypatch.setattr(t, "call_app_login", mock_call_app_login)

    @pytest.mark.usefixtures(
        "_patch_which",
        "_patch_version",
        "_patch_call_app_login",
    )
    def test_success(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(t, "attempt_get_app_config", lambda _: {})
        monkeypatch.setattr(
            t,
            "call_app_config",
            lambda _: {
                "uri": "https://example.com",
                "ca": "/no/this/file",
                "cert": "/mock/data",
                "key": "/mock/data",
            },
        )
        monkeypatch.setattr("builtins.open", mock_open(read_data=b"test"))

        assert t.get_connection_info({"app": "test"}) == t.AppConnectionInfo(
            uri="https://example.com",
            ca=None,
            cert=b"test",
            key=b"test",
        )

    def test_missing_dependency(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr("shutil.which", lambda _: None)
        with pytest.raises(UnsupportedError):
            t.get_connection_info({"app": "test"})

    @pytest.mark.usefixtures("_patch_which")
    def test_internal_error(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(t, "call_version", lambda: False)
        with pytest.raises(SecretsEnvError):
            t.get_connection_info({"app": "test"})

    @pytest.mark.usefixtures("_patch_which", "_patch_version", "_patch_call_app_login")
    def test_no_config(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(t, "call_app_config", lambda _: {})
        with pytest.raises(AuthenticationError):
            t.get_connection_info({"app": "test"})


class TestAttemptGetAppConfig:
    def test_success(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(
            t,
            "call_app_config",
            lambda _: {
                "uri": "https://example.com",
                "ca": "/no/this/file",
                "cert": __file__,
                "key": __file__,
            },
        )
        monkeypatch.setattr(t, "is_certificate_valid", lambda _: True)

        assert t.attempt_get_app_config("test") == {
            "uri": "https://example.com",
            "ca": "/no/this/file",
            "cert": __file__,
            "key": __file__,
        }

    def test_missing_dependency(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr("importlib.util.find_spec", lambda _: False)
        assert t.attempt_get_app_config("test") == {}

    def test_no_config(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(t, "call_app_config", lambda _: {})
        assert t.attempt_get_app_config("test") == {}

    def test_not_valid(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(t, "call_app_config", lambda _: {"cert": __file__})
        monkeypatch.setattr(t, "is_certificate_valid", lambda _: False)
        assert t.attempt_get_app_config("test") == {}


class TestIsCertificateValid:
    def test_true(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr("builtins.open", mock_open())

        mock_cert = Mock(spec=cryptography.x509.Certificate)
        mock_cert.not_valid_after = datetime.datetime.now() + datetime.timedelta(30)
        monkeypatch.setattr(
            "cryptography.x509.load_pem_x509_certificate", lambda _: mock_cert
        )

        assert t.is_certificate_valid("test") is True

    def test_false(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr("builtins.open", mock_open(read_data=fake_cert))
        assert t.is_certificate_valid("test") is False


class TestCallVersion:
    @pytest.mark.skipif(no_teleport_cli, reason="Teleport CLI not installed")
    def test_success(self, caplog: pytest.LogCaptureFixture):
        with caplog.at_level(logging.DEBUG):
            assert t.call_version() is True
        assert re.search(r"< Teleport v\d+\.\d+\.\d+", caplog.text)

    def test_fail(self):
        mock = Mock(spec=Run, return_code=1)
        mock.returncode = 1
        with patch.object(t, "run_teleport", return_value=mock):
            assert t.call_version() is False


class TestCallAppConfig:
    def test_success(self):
        mock = Mock(spec=Run, return_code=0)
        mock.stdout = b'{"foo": "bar"}'
        with patch.object(t, "run_teleport", return_value=mock):
            assert t.call_app_config("test") == {"foo": "bar"}

    def test_fail(self):
        mock = Mock(spec=Run, return_code=1)
        with patch.object(t, "run_teleport", return_value=mock):
            assert t.call_app_config("test") == {}


class TestCallAppLogin:
    @pytest.fixture()
    def runner(self):
        runner = Mock(spec=Run, return_code=0)
        runner.iter_any_output.return_value = []
        return runner

    def test_success(
        self,
        caplog: pytest.LogCaptureFixture,
        monkeypatch: pytest.MonkeyPatch,
        runner: Run,
    ):
        # setup mock
        runner.iter_any_output.return_value = [
            "If browser...",
            " http://127.0.0.1:12345/mock",
            "Logged into app test",
        ]

        def mock_run_command(cmd: list):
            assert cmd == [
                "tsh",
                "app",
                "login",
                "--proxy=proxy.example.com",
                "--cluster=stg.example.com",
                "--user=user",
                "test",
            ]
            return runner

        monkeypatch.setattr(t, "Run", mock_run_command)

        # run
        with caplog.at_level(logging.INFO):
            assert (
                t.call_app_login(
                    {
                        "proxy": "proxy.example.com",
                        "cluster": "stg.example.com",
                        "user": "user",
                        "app": "test",
                    }
                )
                is None
            )

        # test
        assert "Waiting for response from Teleport..." in caplog.text
        assert "Successfully logged into app test" in caplog.text

    def test_app_not_found(self, runner: Run):
        runner.return_code = 1
        runner.stderr = 'ERROR: app "test" not found'

        with pytest.raises(
            AuthenticationError, match="Teleport app 'test' not found"
        ), patch.object(t, "Run", return_value=runner):
            assert t.call_app_login({"app": "test"}) is None

    def test_other_error(self, runner: Run):
        runner.return_code = 1
        runner.stderr = "ERROR: mocked"

        with pytest.raises(
            AuthenticationError, match="Teleport error: ERROR: mocked"
        ), patch.object(t, "Run", return_value=runner):
            assert t.call_app_login({"app": "test"}) is None


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
