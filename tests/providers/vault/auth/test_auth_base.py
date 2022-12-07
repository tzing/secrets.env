import pytest

import secrets_env.providers.vault.auth.base as t


def test_auth_method():
    with pytest.raises(NotImplementedError):
        t.Auth.method()
