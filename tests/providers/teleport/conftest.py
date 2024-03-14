import pytest

from secrets_env.providers.teleport.config import TeleportConnectionParameter


@pytest.fixture()
def conn_param():
    return TeleportConnectionParameter(
        uri="https://example.com",
        ca=b"subject=/C=XX/L=Default City/O=Test\n-----MOCK CERTIFICATE-----",
        cert=b"-----MOCK CERTIFICATE-----",
        key=b"-----MOCK PRIVATE KEY-----",
    )
