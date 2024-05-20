from pathlib import Path

import click.testing

from secrets_env.commands.config import group


class TestParse:
    def test_success(self, tmp_path: Path):
        config_file = tmp_path / "config.toml"
        config_file.write_text(
            """
            [[sources]]
            name = "strongbox"
            url = "https://vault.example.com/"
            type = "vault"
            auth = "oidc"
            teleport = "demo"

            [[secrets]]
            name = "DEMO"
            source = "strongbox"
            path = "kv2/test"
            field = ["test", "name.with-dot"]
            """
        )

        runner = click.testing.CliRunner()
        result = runner.invoke(group, ["parse", "-f", str(config_file)])

        assert result.exit_code == 0

    def test_config_error(self, tmp_path: Path):
        config_file = tmp_path / "config.toml"
        config_file.write_text(
            """
            [[sources]]
            type = "vault"
            """
        )

        runner = click.testing.CliRunner()
        result = runner.invoke(group, ["parse", "-f", str(config_file)])

        assert result.exit_code == 1
