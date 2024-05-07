import os

import httpx
import pytest

from secrets_env.providers.vault import VaultKvProvider


@pytest.fixture()
def intl_provider() -> VaultKvProvider:
    if "VAULT_ADDR" not in os.environ:
        raise pytest.skip("VAULT_ADDR is not set")
    if "VAULT_TOKEN" not in os.environ:
        raise pytest.skip("VAULT_TOKEN is not set")
    return VaultKvProvider(auth="token")


@pytest.fixture()
def intl_client(intl_provider: VaultKvProvider) -> httpx.Client:
    return intl_provider.client
