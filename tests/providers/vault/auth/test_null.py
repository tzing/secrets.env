import secrets_env.providers.vault.auth.null as t


class TestNoAuth:
    def test_method(self):
        assert isinstance(t.NoAuth.method(), str)

    def test_login(self):
        auth = t.NoAuth()
        assert auth.login(object()) is None

    def test_load(self):
        assert isinstance(t.NoAuth.load({}), t.NoAuth)
