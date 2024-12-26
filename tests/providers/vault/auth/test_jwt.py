import httpx
import pytest
import respx

from secrets_env.exceptions import AuthenticationError
from secrets_env.providers.vault.auth.jwt import JwtAuth


class TestJwtAuth:
    def test_login__success(
        self, unittest_respx: respx.MockRouter, unittest_client: httpx.Client
    ):
        unittest_respx.post("/v1/auth/jwt/login").mock(
            httpx.Response(
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

        auth = JwtAuth(token="token", role="test-role")

        assert auth.login(unittest_client) == "38fe9691-e623-7238-f618-c94d4e7bc674"

    def test_login__fail(
        self, unittest_respx: respx.MockRouter, unittest_client: httpx.Client
    ):
        unittest_respx.post("/v1/auth/jwt/login").mock(httpx.Response(403))

        auth = JwtAuth(token="token", role=None)
        with pytest.raises(
            AuthenticationError, match="Failed to authenticate using JWT method"
        ):
            auth.login(unittest_client)
