from pathlib import Path
from unittest.mock import Mock, patch

import pytest

import secrets_env.config.parser as t
from secrets_env.providers.vault.auth import Auth
from secrets_env.providers.vault.auth.null import NoAuth


class TestParseConfig:
    @pytest.fixture()
    def _patch_source_parser(self, monkeypatch: pytest.MonkeyPatch):
        def mock_parser(data: dict):
            assert isinstance(data, dict)
            return {"url": "https://example.com", "auth": NoAuth()}

        monkeypatch.setattr(t, "parse_section_source", mock_parser)

    @pytest.fixture()
    def _patch_secrets_parser(self, monkeypatch: pytest.MonkeyPatch):
        def mock_parser(data: dict):
            assert isinstance(data, dict)
            return {"TEST": ("foo", "bar")}

        monkeypatch.setattr(t, "parse_section_secret", mock_parser)

    @pytest.mark.usefixtures("_patch_source_parser")
    @pytest.mark.usefixtures("_patch_secrets_parser")
    def test_success(self):
        cfg = t.parse_config(
            {
                "source": {"url": "https://example.com/"},
                "secrets": {"TEST": "sample#foo"},
            }
        )
        assert isinstance(cfg, dict)
        assert cfg["client"] == {"url": "https://example.com", "auth": NoAuth()}
        assert cfg["secrets"] == {"TEST": ("foo", "bar")}

    def test_skip_parsing(self):
        cfg = t.parse_config(
            {
                "source": {"url": "https://example.com/"},
                "secrets": {},
            }
        )
        assert cfg is None

    @pytest.mark.usefixtures("_patch_secrets_parser")
    def test_invalid_source(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(t, "parse_section_source", lambda _: None)

        cfg = t.parse_config(
            {
                "source": {"arg": "invalid-input"},
                "secrets": {"TEST": "sample#foo"},
            }
        )
        assert cfg is None

    @pytest.mark.usefixtures("_patch_source_parser")
    def test_invalid_secret(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(t, "parse_section_source", lambda _: None)

        cfg = t.parse_config(
            {
                "source": {"url": "https://example.com/"},
                "secrets": {"@arg": "invalid-input"},
            }
        )
        assert cfg is None


class TestParseSectionSource:
    def setup_method(self):
        self.data = {"url": "https://example.com", "auth": "null", "tls": {}}

    @pytest.mark.usefixtures("_disable_ensure_path_exist_check")
    @pytest.mark.parametrize(
        ("cfg_ca_cert", "ca_cert"),
        [
            ({}, None),
            ({"ca_cert": "/data/ca.cert"}, Path("/data/ca.cert")),
        ],
    )
    @pytest.mark.parametrize(
        ("cfg_client_cert", "client_cert"),
        [
            ({}, None),
            ({"client_cert": "/data/client.pem"}, Path("/data/client.pem")),
            (
                {"client_cert": "/data/client.pem", "client_key": "/data/client.key"},
                (Path("/data/client.pem"), Path("/data/client.key")),
            ),
        ],
    )
    def test_success(self, cfg_ca_cert, ca_cert, cfg_client_cert, client_cert):
        # setup
        self.data["tls"].update(cfg_ca_cert)
        self.data["tls"].update(cfg_client_cert)

        # run
        cfg = t.parse_section_source(self.data)

        # test
        assert isinstance(cfg, dict)
        assert cfg["url"] == "https://example.com"
        assert cfg["auth"] == NoAuth()

        if ca_cert:
            assert cfg["ca_cert"] == ca_cert
        else:
            assert "ca_cert" not in cfg

        if client_cert:
            assert cfg["client_cert"] == client_cert
        else:
            assert "client_cert" not in cfg

    def test_fail(self):
        with patch.object(t, "get_url", return_value=None):
            assert t.parse_section_source(self.data) is None

        with patch.object(t, "get_auth", return_value=None):
            assert t.parse_section_source(self.data) is None

        with patch.object(t, "get_tls_ca_cert", return_value=(None, False)):
            assert t.parse_section_source(self.data) is None

        with patch.object(t, "get_tls_client_cert", return_value=(None, False)):
            assert t.parse_section_source(self.data) is None

        # make sure the errors above are not caused by malformed data dict
        assert isinstance(t.parse_section_source(self.data), dict)


class TestGetAuth:
    @pytest.fixture()
    def _patch_get_auth(self, monkeypatch: pytest.MonkeyPatch):
        def mock_get_auth(method: str, _):
            assert method == "test"
            return Mock(spec=Auth)

        monkeypatch.setattr("secrets_env.providers.vault.auth.get_auth", mock_get_auth)

    @pytest.mark.usefixtures("_patch_get_auth")
    def test_from_data(self):
        assert isinstance(t.get_auth({"method": "test"}), Auth)

    @pytest.mark.usefixtures("_patch_get_auth")
    def test_from_env(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("SECRETS_ENV_METHOD", "test")
        assert isinstance(t.get_auth({}), Auth)

    @pytest.mark.usefixtures("_patch_get_auth")
    def test_syntax_sugar(self):
        assert isinstance(t.get_auth("test"), Auth)

    def test_type_error(self):
        assert t.get_auth({"method": 1234}) is None

    def test_default_method(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ):
        def mock_get_auth(method: str, _):
            assert method == "token"
            return Mock(spec=Auth)

        monkeypatch.setattr("secrets_env.providers.vault.auth.get_auth", mock_get_auth)

        assert isinstance(t.get_auth({}), Auth)
        assert (
            "Missing required config <mark>auth method</mark>. "
            "Use default method <data>token</data>"
        ) in caplog.text


class TestGetTLS:
    def test_get_tls_ca_cert(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
        path = tmp_path / "ca.cert"
        path.touch()

        # success
        with monkeypatch.context() as ctx:
            ctx.setenv("SECRETS_ENV_CA_CERT", str(path))
            assert t.get_tls_ca_cert({}) == (path, True)

        assert t.get_tls_ca_cert({"ca_cert": str(path)}) == (path, True)

        assert t.get_tls_ca_cert({}) == (None, True)

        # fail
        with monkeypatch.context() as ctx:
            ctx.setenv("SECRETS_ENV_CA_CERT", "/data/no-this-file")
            assert t.get_tls_ca_cert({}) == (None, False)

    def test_get_tls_client_cert(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        caplog: pytest.LogCaptureFixture,
    ):
        client_cert = tmp_path / "client.pem"
        client_cert.touch()

        client_key = tmp_path / "client.key"
        client_key.touch()

        # success: from env var
        with monkeypatch.context() as ctx:
            ctx.setenv("SECRETS_ENV_CLIENT_CERT", str(client_cert))
            assert t.get_tls_client_cert({}) == (client_cert, True)

        # success: from config
        assert t.get_tls_client_cert(
            {
                "client_cert": str(client_cert),
                "client_key": str(client_key),
            }
        ) == ((client_cert, client_key), True)

        # success: no data
        assert t.get_tls_client_cert({}) == (None, True)

        # fail: only key
        with monkeypatch.context() as ctx:
            ctx.setenv("SECRETS_ENV_CLIENT_KEY", str(client_key))
            assert t.get_tls_client_cert({}) == (None, False)
            assert "Missing config <mark>client_cert</mark>." in caplog.text

        # fail: file not exist
        assert t.get_tls_client_cert(
            {
                "client_cert": "/data/no-this-file",
            }
        ) == (None, False)


def test_parse_section_secret(caplog: pytest.LogCaptureFixture):
    assert t.parse_section_secret(
        {
            "var1": "foo#bar",
            "_VAR2": {"path": "foo", "field": "bar"},
            "var3:invalid_name": "foo#bar",
        }
    ) == {
        "var1": ("foo", "bar"),
        "_VAR2": ("foo", "bar"),
    }

    assert (
        "Invalid environment variable name <data>var3:invalid_name</data>."
        in caplog.text
    )


class TestGetSecretSource:
    def test_success(self):
        # str
        assert t.get_secret_source("test", "foo#bar") == ("foo", "bar")
        assert t.get_secret_source("test", "foo#b") == ("foo", "b")
        assert t.get_secret_source("test", "f#bar") == ("f", "bar")

        # dict
        assert t.get_secret_source(
            "test",
            {"path": "foo", "field": "bar"},
        ) == ("foo", "bar")

    @pytest.mark.parametrize(
        ("input_", "err_msg"),
        [
            # empty
            ("", "Empty input"),
            (None, "Empty input"),
            ({}, "Empty input"),
            # malformed str
            ("foo", "Missing delimiter '#'"),
            ("#bar", "Missing secret path"),
            ("foo#", "Missing secret field"),
            # malformed dict
            ({"field": "bar"}, "Missing secret path"),
            ({"path": "foo", "field": 1234}, "Invalid type of field"),
            ({"path": "foo"}, "Missing secret field"),
            ({"path": 1234, "field": "bar"}, "Invalid type of path"),
            # other
            (1234, "Invalid type"),
        ],
    )
    def test_fail(self, caplog: pytest.LogCaptureFixture, input_, err_msg: str):
        assert t.get_secret_source("test", input_) is None
        assert "Target secret <data>test</data> is invalid." in caplog.text
        assert err_msg in caplog.text
