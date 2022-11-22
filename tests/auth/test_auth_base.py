import httpx
import pytest

import secrets_env.auth.base as t


def test_auth_base():
    with pytest.raises(NotImplementedError):
        t.Auth.method()


def test_no_auth(unittest_client: httpx.Client):
    auth = t.NoAuth.load({})
    assert isinstance(auth, t.NoAuth)
    assert isinstance(auth.method(), str)
    assert auth.login(unittest_client) is None
