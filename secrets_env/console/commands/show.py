from __future__ import annotations

import enum
import itertools
import logging
import math
import typing
from pathlib import Path

import click
from pydantic import BaseModel

import secrets_env.config
from secrets_env.console.core import entrypoint, with_output_options
from secrets_env.exceptions import ConfigError

if typing.TYPE_CHECKING:
    from typing import Iterator

    TableValue = dict[str, "TableValue"] | list["TableValue"] | str
    Table = dict[str, TableValue]

logger = logging.getLogger(__name__)

INDENT_SIZE = 4
INDENT = " " * INDENT_SIZE


@entrypoint.command()
@click.option(
    "-f",
    "--config",
    type=click.Path(exists=True, file_okay=True, path_type=Path),
    help="Specify configuration file.",
)
@with_output_options
def show(config: Path | None):
    """
    Print the contents of the configuration file to the console.

    It provides insight into how secrets.env interprets the configuration file.
    It also identifies some critical errors. However, it's important to note that
    certain errors are only evaluated during runtime, so this command may not
    detect all potential issues.
    """
    try:
        cfg = secrets_env.config.load_local_config(config)
    except ConfigError:
        raise click.Abort from None

    # sources
    click.echo(click.style("Sources:", fg="cyan"))
    for i, source in enumerate(cfg.providers.values()):
        print_model(i, source.name, source)

    # requests
    click.echo(click.style("Secrets:", fg="cyan"))
    for i, request in enumerate(cfg.requests):
        print_model(i, request.name, request)


def print_model(index: int, name: str, model: BaseModel) -> None:
    # heading
    output_index = f"\t#{index}\t".expandtabs(INDENT_SIZE)
    output_index = click.style(output_index, fg="green")
    output_name = click.style(name, fg="yellow")
    click.echo(f"{output_index}{output_name}")

    # body
    table = _model_to_table(model)
    for line in _table_to_lines(table):
        click.echo(INDENT * 2 + line)

    # tailing
    click.echo()


def _model_to_table(model: BaseModel) -> Table:
    data = {}
    for field_name in itertools.chain(model.__class_vars__, model.model_fields):
        data[field_name] = getattr(model, field_name)
    return _dict_to_table(data)


def _dict_to_table(d: dict) -> Table:
    table = {}
    for field_name, field_value in d.items():
        # formating key
        key = " ".join(word.capitalize() for word in field_name.split("_"))

        # formating value
        if field_value is None:
            continue
        elif isinstance(field_value, BaseModel):
            value = _model_to_table(field_value)
        elif isinstance(field_value, dict):
            value = _dict_to_table(field_value)
        elif isinstance(field_value, list):
            value = field_value
        elif isinstance(field_value, enum.Enum):
            value = click.style(field_value.name, fg="blue")
        else:
            value = str(field_value)

        table[key] = value

    return table


def _table_to_lines(table: Table) -> Iterator[str]:
    if not table:
        return

    max_field_name_length = max(map(len, table)) + 2
    field_name_width = math.ceil(max_field_name_length / INDENT_SIZE) * INDENT_SIZE

    for field_name, field_value in table.items():
        field_name = f"{field_name}: ".ljust(field_name_width)
        field_name = click.style(field_name, fg="cyan")

        if isinstance(field_value, dict) and field_value:
            yield field_name
            for line in _table_to_lines(field_value):
                yield INDENT + line

        elif isinstance(field_value, list) and field_value:
            yield field_name
            list_prefix = INDENT + click.style("-", fg="blue")
            for item in field_value:
                yield f"{list_prefix} {item}"

        else:
            yield f"{field_name}{field_value}"
