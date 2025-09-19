import re

import httpx
import pytest
import respx
from httpx import AsyncClient, Response

from secrets_env.exceptions import AuthenticationError
from secrets_env.providers.vault.auth.jwt import JwtAuth


@pytest.fixture
def route(respx_mock: respx.MockRouter) -> respx.Route:
    return respx_mock.post("https://example.com/v1/auth/jwt/login")


class TestJwtAuth:

    @pytest.mark.asyncio
    async def test_login__success(self, route: respx.Route):
        route.mock(
            Response(
                200,
                json={
                    "auth": {
                        "client_token": "38fe9691-e623-7238-f618-c94d4e7bc674",
                        "accessor": "78e87a38-84ed-2692-538f-ca8b9f400ab3",
                        "policies": ["default"],
                        "metadata": {"role": "demo"},
                        "lease_duration": 2764800,
                        "renewable": True,
                    }
                },
            )
        )

        auth = JwtAuth.model_validate({"token": "token", "role": "test-role"})
        client = AsyncClient(base_url="https://example.com")

        assert await auth.login(client) == "38fe9691-e623-7238-f618-c94d4e7bc674"

    @pytest.mark.asyncio
    async def test_login__fail(self, route: respx.Route):
        route.mock(httpx.Response(403))

        auth = JwtAuth.model_validate({"token": "token", "role": None})
        client = AsyncClient(base_url="https://example.com")

        with pytest.raises(
            AuthenticationError,
            match=re.escape("Failed to authenticate using JWT method"),
        ):
            await auth.login(client)
