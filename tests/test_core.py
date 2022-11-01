from pathlib import Path
from unittest.mock import Mock, patch

import httpx
import httpx._config
import pytest
import respx

import secrets_env.auth
import secrets_env.core as t
from secrets_env.exception import AuthenticationError


class TestKVReader:
    def setup_method(self):
        self.auth = Mock(spec=secrets_env.auth.Auth)
        self.auth.method.return_value = "mocked"

    def test___init__type_errors(self):
        with pytest.raises(TypeError):
            t.KVReader(1234, self.auth)
        with pytest.raises(TypeError):
            t.KVReader("https://example.com", 1234)
        with pytest.raises(TypeError):
            t.KVReader("https://example.com", self.auth, ca_cert="/path/cert")
        with pytest.raises(TypeError):
            t.KVReader("https://example.com", self.auth, client_cert="/path/cert")
        with pytest.raises(TypeError):
            t.KVReader("https://example.com", self.auth, client_key="/path/cert")

    def test_client(self):
        reader = t.KVReader(url="https://example.com/", auth=self.auth)

        # fail
        self.auth.login.return_value = None
        with pytest.raises(AuthenticationError):
            reader.client

        self.auth.login.return_value = "test-token"
        with pytest.raises(AuthenticationError), patch.object(
            t, "is_authenticated", return_value=False
        ):
            reader.client

        # success
        with patch.object(t, "is_authenticated", return_value=True):
            assert isinstance(reader.client, httpx.Client)
            assert isinstance(reader.client, httpx.Client)  # from cache


def test_create_client(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    # disable cert format check
    monkeypatch.setattr(
        httpx._config.SSLConfig, "load_ssl_context_verify", lambda _: None
    )

    path = tmp_path / "test.pem"

    # no error could be enough
    t.create_client("http://example.com", None, None, None)
    t.create_client("http://example.com", path, None, None)
    t.create_client("http://example.com", path, path, None)
    t.create_client("http://example.com", path, path, path)


def test_is_authenticated():
    # use real client
    client = httpx.Client(base_url="http://localhost:8200")
    assert t.is_authenticated(client, "!ntegr@t!0n-test")
    assert not t.is_authenticated(client, "invalid-token")


class TestGetMountPoint:
    URL = "http://example.com/v1/sys/internal/ui/mounts/secrets/test"

    @pytest.fixture()
    def route(self, respx_mock: respx.MockRouter):
        return respx_mock.get(
            "http://example.com/v1/sys/internal/ui/mounts/secrets/test"
        )

    def setup_method(self):
        self.client = httpx.Client(base_url="http://example.com")

    def test_success_kv1(self, route: respx.Route):
        route.mock(
            httpx.Response(
                200,
                json={
                    "request_id": "01eef618-15b2-0445-4768-fae2f953e25d",
                    "lease_id": "",
                    "renewable": False,
                    "lease_duration": 0,
                    "data": {
                        "accessor": "kv_92250a43",
                        "config": {
                            "default_lease_ttl": 0,
                            "force_no_cache": False,
                            "max_lease_ttl": 0,
                        },
                        "description": "",
                        "external_entropy_access": False,
                        "local": False,
                        "options": {"version": "1"},
                        "path": "secrets/",
                        "seal_wrap": False,
                        "type": "kv",
                        "uuid": "f26f43ad-5e58-c739-be4a-a6fb29481bc0",
                    },
                    "wrap_info": None,
                    "warnings": None,
                    "auth": None,
                },
            )
        )
        assert t.get_mount_point(self.client, "secrets/test") == ("secrets/", 1)

    def test_success_kv2(self, route: respx.Route):
        route.mock(
            httpx.Response(
                200,
                json={
                    "request_id": "989b476f-1f1d-c493-0777-8f7e9823a3c8",
                    "lease_id": "",
                    "renewable": False,
                    "lease_duration": 0,
                    "data": {
                        "accessor": "kv_8e4430be",
                        "config": {
                            "default_lease_ttl": 0,
                            "force_no_cache": False,
                            "max_lease_ttl": 0,
                        },
                        "description": "",
                        "external_entropy_access": False,
                        "local": False,
                        "options": {"version": "2"},
                        "path": "secrets/",
                        "seal_wrap": False,
                        "type": "kv",
                        "uuid": "1dc09fc2-4844-f332-b08d-845fcb754545",
                    },
                    "wrap_info": None,
                    "warnings": None,
                    "auth": None,
                },
            )
        )
        assert t.get_mount_point(self.client, "secrets/test") == ("secrets/", 2)

    def test_success_legacy(self, route: respx.Route):
        route.mock(httpx.Response(404))
        assert t.get_mount_point(self.client, "secrets/test") == ("", 1)

    def test_not_ported_version(self, route: respx.Route):
        route.mock(
            httpx.Response(
                200,
                json={
                    "data": {
                        "path": "mock/",
                        "type": "kv",
                        "options": {"version": "99"},
                    }
                },
            )
        )
        assert t.get_mount_point(self.client, "secrets/test") == (None, None)

    def test_bad_request(self, route: respx.Route, caplog: pytest.LogCaptureFixture):
        route.mock(httpx.Response(400))
        assert t.get_mount_point(self.client, "secrets/test") == (None, None)
        assert "Error occurred during checking metadata for secrets/test" in caplog.text

    def test_connection_error(
        self, route: respx.Route, caplog: pytest.LogCaptureFixture
    ):
        route.mock(side_effect=httpx.ConnectError)
        assert t.get_mount_point(self.client, "secrets/test") == (None, None)
        assert (
            "Error occurred during checking metadata for secrets/test: connection error"
            in caplog.text
        )

    def test_other_error(self, route: respx.Route):
        route.mock(side_effect=httpx.DecodingError)
        with pytest.raises(httpx.DecodingError):
            t.get_mount_point(self.client, "secrets/test")
