import os
from unittest.mock import AsyncMock

import httpx
import pytest
import respx
from httpx import AsyncClient, Response
from pydantic_core import ValidationError

from secrets_env.providers.vault.api import (
    MountMetadata,
    get_mount,
    is_authenticated,
    read_secret,
)


@pytest.fixture
def ut_client() -> AsyncClient:
    return AsyncClient(base_url="https://example.com")


@pytest.fixture
def intl_client() -> AsyncClient:
    if "VAULT_ADDR" not in os.environ:
        pytest.skip("VAULT_ADDR is not set")
    if "VAULT_TOKEN" not in os.environ:
        pytest.skip("VAULT_TOKEN is not set")
    return AsyncClient(
        base_url=os.environ["VAULT_ADDR"],
        headers={
            "Accept": "application/json",
            "X-Vault-Token": os.environ["VAULT_TOKEN"],
        },
    )


class TestIsAuthenticated:

    @pytest.mark.asyncio
    async def test_success(self, respx_mock: respx.MockRouter):
        respx_mock.get("https://vault.example.com/v1/auth/token/lookup-self")

        client = AsyncClient(base_url="https://vault.example.com")
        assert await is_authenticated(client, "test-token") is True

    @pytest.mark.asyncio
    async def test_fail(self, respx_mock: respx.MockRouter):
        respx_mock.get("https://vault.example.com/v1/auth/token/lookup-self").respond(
            status_code=403,
            json={"errors": ["mock permission denied"]},
        )

        client = AsyncClient(base_url="https://vault.example.com")
        assert await is_authenticated(client, "test-token") is False

    @pytest.mark.asyncio
    async def test_integration(self):
        if "VAULT_ADDR" not in os.environ:
            raise pytest.skip("VAULT_ADDR is not set")
        if "VAULT_TOKEN" not in os.environ:
            raise pytest.skip("VAULT_TOKEN is not set")

        client = AsyncClient(base_url=os.environ["VAULT_ADDR"])

        assert await is_authenticated(client, os.environ["VAULT_TOKEN"]) is True
        assert await is_authenticated(client, "invalid-token") is False


class TestReadSecret:

    @pytest.fixture
    def _set_mount_kv2(self, monkeypatch: pytest.MonkeyPatch):
        async def _get_mount(client: AsyncClient, path: str):
            return MountMetadata(path="secrets/", version=2)

        monkeypatch.setattr("secrets_env.providers.vault.api.get_mount", _get_mount)

    @pytest.mark.asyncio
    @pytest.mark.usefixtures("_set_mount_kv2")
    async def test_kv2(self, respx_mock: respx.MockRouter, ut_client: AsyncClient):
        respx_mock.get("https://example.com/v1/secrets/data/test").mock(
            Response(
                200,
                json={
                    "request_id": "9ababbb6-3749-cf2c-5a5b-85660e917e8e",
                    "lease_id": "",
                    "renewable": False,
                    "lease_duration": 0,
                    "data": {
                        "data": {"test": "mock"},
                        "metadata": {
                            "created_time": "2022-09-20T15:57:45.143053836Z",
                            "custom_metadata": None,
                            "deletion_time": "",
                            "destroyed": False,
                            "version": 1,
                        },
                    },
                    "wrap_info": None,
                    "warnings": None,
                    "auth": None,
                },
            )
        )

        assert await read_secret(ut_client, "secrets/test") == {"test": "mock"}

    @pytest.mark.asyncio
    async def test_kv2_integration(self, intl_client: AsyncClient):
        assert await read_secret(intl_client, "kv2/test") == {
            "foo": "hello, world",
            "test": {"name.with-dot": "sample-value"},
        }

    @pytest.mark.asyncio
    async def test_kv1(
        self,
        monkeypatch: pytest.MonkeyPatch,
        respx_mock: respx.MockRouter,
        ut_client: AsyncClient,
    ):
        monkeypatch.setattr(
            "secrets_env.providers.vault.api.get_mount",
            AsyncMock(return_value=MountMetadata(path="secrets/", version=1)),
        )
        respx_mock.get("https://example.com/v1/secrets/test").mock(
            httpx.Response(
                200,
                json={
                    "request_id": "a8f28d97-8a9d-c9dd-4d86-e815083b33ad",
                    "lease_id": "",
                    "renewable": False,
                    "lease_duration": 2764800,
                    "data": {"test": "mock"},
                    "wrap_info": None,
                    "warnings": None,
                    "auth": None,
                },
            )
        )

        assert await read_secret(ut_client, "secrets/test") == {"test": "mock"}

    @pytest.mark.asyncio
    async def test_kv1_integration(self, intl_client: AsyncClient):
        assert await read_secret(intl_client, "kv1/test") == {"foo": "hello"}

    @pytest.mark.asyncio
    @pytest.mark.usefixtures("_set_mount_kv2")
    async def test_forbidden(
        self,
        respx_mock: respx.MockRouter,
        ut_client: AsyncClient,
        caplog: pytest.LogCaptureFixture,
    ):
        respx_mock.get("https://example.com/v1/secrets/data/test").mock(
            httpx.Response(403)
        )
        assert await read_secret(ut_client, "secrets/test") is None
        assert "Permission denied for secret <data>secrets/test</data>" in caplog.text

    @pytest.mark.asyncio
    @pytest.mark.usefixtures("_set_mount_kv2")
    async def test_not_found(
        self,
        respx_mock: respx.MockRouter,
        ut_client: AsyncClient,
        caplog: pytest.LogCaptureFixture,
    ):
        respx_mock.get("https://example.com/v1/secrets/data/test").mock(
            httpx.Response(404)
        )
        assert await read_secret(ut_client, "secrets/test") is None
        assert "Secret <data>secrets/test</data> not found" in caplog.text

    @pytest.mark.asyncio
    async def test_get_mount_error(
        self, monkeypatch: pytest.MonkeyPatch, ut_client: AsyncClient
    ):
        monkeypatch.setattr(
            "secrets_env.providers.vault.api.get_mount",
            AsyncMock(return_value=None),
        )
        assert await read_secret(ut_client, "secrets/test") is None

    @pytest.mark.asyncio
    @pytest.mark.usefixtures("_set_mount_kv2")
    async def test_connection_error(
        self,
        respx_mock: respx.MockRouter,
        ut_client: AsyncClient,
        caplog: pytest.LogCaptureFixture,
    ):
        respx_mock.get("https://example.com/v1/secrets/data/test").mock(
            side_effect=httpx.ProxyError
        )
        assert await read_secret(ut_client, "secrets/test") is None
        assert (
            "Error occurred during query secret secrets/test: proxy error"
            in caplog.text
        )

    @pytest.mark.asyncio
    @pytest.mark.usefixtures("_set_mount_kv2")
    async def test_http_exception(
        self, respx_mock: respx.MockRouter, ut_client: AsyncClient
    ):
        respx_mock.get("https://example.com/v1/secrets/data/test").mock(
            side_effect=httpx.DecodingError
        )
        with pytest.raises(httpx.DecodingError):
            await read_secret(ut_client, "secrets/test")

    @pytest.mark.asyncio
    @pytest.mark.usefixtures("_set_mount_kv2")
    async def test_bad_request(
        self,
        respx_mock: respx.MockRouter,
        ut_client: AsyncClient,
        caplog: pytest.LogCaptureFixture,
    ):
        respx_mock.get("https://example.com/v1/secrets/data/test").mock(
            httpx.Response(499)
        )
        assert await read_secret(ut_client, "secrets/test") is None
        assert (
            "Error occurred during query secret <data>secrets/test</data>"
            in caplog.text
        )


class TestGetMount:

    @pytest.fixture
    def route(self, respx_mock: respx.MockRouter):
        return respx_mock.get(
            "https://example.com/v1/sys/internal/ui/mounts/secrets/test"
        )

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("response", "expected"),
        [
            # kv2
            (
                Response(
                    200,
                    json={
                        "data": {
                            "options": {"version": "2"},
                            "path": "secrets/",
                            "type": "kv",
                        }
                    },
                ),
                MountMetadata(path="secrets/", version=2),
            ),
            # kv1
            (
                Response(
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
                ),
                MountMetadata(path="secrets/", version=1),
            ),
            # legacy
            (
                Response(404),
                MountMetadata(path="", version=1),
            ),
        ],
    )
    async def test_success(
        self,
        route: respx.Route,
        response: Response,
        ut_client: AsyncClient,
        expected: MountMetadata,
    ):
        route.mock(response)
        assert await get_mount(ut_client, "secrets/test") == expected

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("path", "expect"),
        [
            ("kv2/test", MountMetadata(path="kv2/", version=2)),
            ("kv1/test", MountMetadata(path="kv1/", version=1)),
        ],
    )
    async def test_success_integration(
        self, intl_client: AsyncClient, path: str, expect: MountMetadata
    ):
        assert await get_mount(intl_client, path) == expect

    @pytest.mark.asyncio
    async def test_not_ported_version(self, route: respx.Route, ut_client: AsyncClient):
        route.mock(
            Response(
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
            await get_mount(ut_client, "secrets/test")

    @pytest.mark.asyncio
    async def test_bad_request(
        self,
        route: respx.Route,
        ut_client: AsyncClient,
        caplog: pytest.LogCaptureFixture,
    ):
        route.mock(Response(400))
        assert await get_mount(ut_client, "secrets/test") is None
        assert "Error occurred during checking metadata for secrets/test" in caplog.text

    @pytest.mark.asyncio
    async def test_connection_error(
        self,
        route: respx.Route,
        ut_client: AsyncClient,
        caplog: pytest.LogCaptureFixture,
    ):
        route.mock(side_effect=httpx.ConnectError)
        assert await get_mount(ut_client, "secrets/test") is None
        assert (
            "Error occurred during checking metadata for secrets/test: connection error"
            in caplog.text
        )

    @pytest.mark.asyncio
    async def test_http_exception(self, route: respx.Route, ut_client: AsyncClient):
        route.mock(side_effect=httpx.DecodingError)
        with pytest.raises(httpx.DecodingError):
            await get_mount(ut_client, "secrets/test")
