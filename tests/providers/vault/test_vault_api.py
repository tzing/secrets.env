import httpx
import pytest
import respx
from pydantic_core import ValidationError

from secrets_env.providers.vault.api import MountMetadata, get_mount


class TestGetMount:
    @pytest.fixture()
    def route(self, respx_mock: respx.MockRouter):
        return respx_mock.get(
            "https://example.com/v1/sys/internal/ui/mounts/secrets/test"
        )

    def test_success_kv2(self, route: respx.Route, unittest_client: httpx.Client):
        route.mock(
            httpx.Response(
                200,
                json={
                    "data": {
                        "options": {"version": "2"},
                        "path": "secrets/",
                        "type": "kv",
                    },
                },
            )
        )
        assert get_mount(unittest_client, "secrets/test") == MountMetadata(
            path="secrets/", version=2
        )

    def test_success_kv2_integration(self, intl_client: httpx.Client):
        assert get_mount(intl_client, "kv2/test") == MountMetadata(
            path="kv2/", version=2
        )

    def test_success_kv1(self, route: respx.Route, unittest_client: httpx.Client):
        route.mock(
            httpx.Response(
                200,
                json={
                    "data": {
                        "options": {"version": "1"},
                        "path": "secrets/",
                        "type": "kv",
                    },
                    "wrap_info": None,
                    "warnings": None,
                    "auth": None,
                },
            )
        )
        assert get_mount(unittest_client, "secrets/test") == MountMetadata(
            path="secrets/", version=1
        )

    def test_success_kv1_integration(self, intl_client: httpx.Client):
        assert get_mount(intl_client, "kv1/test") == MountMetadata(
            path="kv1/", version=1
        )

    def test_success_legacy(self, route: respx.Route, unittest_client: httpx.Client):
        route.mock(httpx.Response(404))
        assert get_mount(unittest_client, "secrets/test") == MountMetadata(
            path="", version=1
        )

    def test_not_ported_version(
        self, route: respx.Route, unittest_client: httpx.Client
    ):
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

        with pytest.raises(ValidationError):
            get_mount(unittest_client, "secrets/test")

    def test_bad_request(
        self,
        route: respx.Route,
        unittest_client: httpx.Client,
        caplog: pytest.LogCaptureFixture,
    ):
        route.mock(httpx.Response(400))
        assert get_mount(unittest_client, "secrets/test") is None
        assert "Error occurred during checking metadata for secrets/test" in caplog.text

    def test_connection_error(
        self,
        route: respx.Route,
        unittest_client: httpx.Client,
        caplog: pytest.LogCaptureFixture,
    ):
        route.mock(side_effect=httpx.ConnectError)
        assert get_mount(unittest_client, "secrets/test") is None
        assert (
            "Error occurred during checking metadata for secrets/test: connection error"
            in caplog.text
        )

    def test_http_exception(self, route: respx.Route, unittest_client: httpx.Client):
        route.mock(side_effect=httpx.DecodingError)
        with pytest.raises(httpx.DecodingError):
            get_mount(unittest_client, "secrets/test")
