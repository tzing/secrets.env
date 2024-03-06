from secrets_env.providers.vault.auth.base import NullAuth


class TestNullAuth:
    def test_login(self):
        auth = NullAuth()
        assert auth.login(object()) is None

    def test_create(self):
        assert isinstance(NullAuth.create("https://example.com/", {}), NullAuth)
