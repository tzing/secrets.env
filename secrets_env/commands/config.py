from __future__ import annotations

import enum
import logging
import math
import typing
from pathlib import Path

import click
from pydantic import BaseModel

import secrets_env.config
from secrets_env.commands.core import entrypoint, with_output_options
from secrets_env.exceptions import ConfigError
from secrets_env.provider import Provider

if typing.TYPE_CHECKING:
    from typing import Iterator

    TableValue = dict[str, "TableValue"] | list["TableValue"] | str
    Table = dict[str, TableValue]

logger = logging.getLogger(__name__)

INDENT_SIZE = 4


@entrypoint.group("config")
def group():
    """
    Manage configuration for secrets.env.
    """


@group.command()
@click.option(
    "-f",
    "--config",
    type=click.Path(exists=True, file_okay=True, path_type=Path),
    help="Specify configuration file.",
)
@with_output_options
def parse(config: Path | None):
    """
    Parse the configuration file and print to the console.
    """
    try:
        cfg = secrets_env.config.load_local_config(config)
    except ConfigError:
        raise click.Abort from None

    # sources
    click.echo(click.style("Sources:", fg="cyan"))

    for i, source in enumerate(cfg.providers.values()):
        print_model(i, source.name or "(anonymous)", source)

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
        click.echo(" " * INDENT_SIZE * 2 + line)

    # tailing
    click.echo()


def _model_to_table(model: BaseModel) -> Table:
    data = {}
    if isinstance(model, Provider):
        data["Type"] = model.type
    for field_name in model.model_fields:
        field_value = getattr(model, field_name)
        data[field_name] = field_value
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
        elif isinstance(field_value, bool):
            value = click.style("True" if field_value else "False", fg="blue")
        elif isinstance(field_value, (int, float)):
            value = click.style(field_value, fg="green")
        else:
            value = str(field_value)

        table[key] = value

    return table


def _table_to_lines(table: Table) -> Iterator[str]:
    if not table:
        return

    max_field_name_length = max(map(len, table))
    field_name_width = (
        math.ceil((max_field_name_length + 2) / INDENT_SIZE) * INDENT_SIZE
    )

    list_prefix = " " * INDENT_SIZE + click.style("-", fg="blue") + " "

    for field_name, field_value in table.items():
        field_name = f"{field_name}: ".ljust(field_name_width)
        field_name = click.style(field_name, fg="cyan")

        if isinstance(field_value, dict):
            if field_value:
                yield field_name
                for line in _table_to_lines(field_value):
                    yield " " * INDENT_SIZE + line
            else:
                yield field_name + "{}"

        elif isinstance(field_value, list):
            if field_value:
                yield field_name
                for item in field_value:
                    yield f"{list_prefix} {item}"
            else:
                yield field_name + "[]"

        else:
            yield f"{field_name}{field_value}"
