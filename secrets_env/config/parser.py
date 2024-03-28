from __future__ import annotations

import contextlib
import re
from typing import TYPE_CHECKING, cast

from pydantic import BaseModel, Field, ValidationError, field_validator, model_validator

from secrets_env.provider import Provider  # noqa: TCH001
from secrets_env.providers import get_provider

if TYPE_CHECKING:
    from typing import Iterator, Sequence

    from pydantic import ValidationInfo
    from pydantic_core import ErrorDetails

    from secrets_env.provider import RequestSpec


class ProviderBuilder(BaseModel):
    """Internal helper to build provider instances from source(s) configs."""

    source: list[Provider] = Field(default_factory=list)
    sources: list[Provider] = Field(default_factory=list)

    @field_validator("source", "sources", mode="before")
    @classmethod
    def _transform(cls, value, info: ValidationInfo):
        field_name = cast(str, info.field_name)

        if isinstance(value, dict):
            value = [value]

        if isinstance(value, list):
            providers = []
            errors = []
            for i, item in enumerate(value):
                with capture_line_errors(errors, (field_name, i)):
                    if isinstance(item, dict):
                        providers.append(get_provider(item))
                    else:
                        providers.append(item)

            if errors:
                raise ValidationError.from_exception_data(
                    title="sources", line_errors=errors
                )
            return providers

        else:
            raise ValidationError.from_exception_data(
                title=field_name,
                line_errors=[
                    {
                        "type": "value_error",
                        "loc": (field_name,),
                        "ctx": {"error": "Input must be a list or a dictionary"},
                    }
                ],
            )

    def iter(self) -> Iterator[Provider]:
        yield from self.source
        yield from self.sources

    def collect(self) -> dict[str, Provider]:
        """
        Returns a dictionary of provider instances by name.

        Raises
        ------
        ValidationError
            If the source names are not unique.
        """
        providers = {}
        errors = []

        for provider in self.iter():
            if provider.name in providers:
                errors.append(
                    {
                        "type": "value_error",
                        "loc": ("sources", "*", "name"),
                        "input": provider.name or "(anonymous)",
                        "ctx": {"error": "duplicate source name"},
                    }
                )
            else:
                providers[provider.name] = provider

        if len(providers) > 1 and None in providers:
            errors.append(
                {
                    "type": "value_error",
                    "loc": ("sources", "*", "name"),
                    "ctx": {
                        "error": "source must have names when using multiple sources",
                    },
                }
            )

        if errors:
            raise ValidationError.from_exception_data(
                title="sources", line_errors=errors
            )

        return providers


class Request(BaseModel):
    name: str
    source: str | None = None

    # all possible fields
    field: str | None = None
    format: str | None = None
    path: str | None = None
    value: str | None = None

    @field_validator("name", mode="after")
    @classmethod
    def _check_name_format(cls, value: str):
        if not re.fullmatch(r"[a-zA-Z_]\w*", value):
            raise ValueError("Invalid environment variable name")
        return value


class RequestBuilder(BaseModel):
    """Internal helper to build request instances from secret(s) configs."""

    secret: list[Request] = Field(default_factory=list)
    secrets: list[Request] = Field(default_factory=list)

    @field_validator("secret", "secrets", mode="before")
    @classmethod
    def _transform(cls, value: list | dict[str, RequestSpec], info: ValidationInfo):
        field_name = cast(str, info.field_name)

        if isinstance(value, list):
            return value

        elif isinstance(value, dict):
            requests = []
            errors = []
            for name, spec in value.items():
                with capture_line_errors(errors, (field_name, name)):
                    if isinstance(spec, dict):
                        requests.append(Request(name=name, **spec))
                    elif isinstance(spec, str):
                        requests.append(Request(name=name, value=spec))
                    else:
                        requests.append(spec)

            if errors:
                raise ValidationError.from_exception_data(
                    title=field_name, line_errors=errors
                )
            return requests

        else:
            raise ValidationError.from_exception_data(
                title=field_name,
                line_errors=[
                    {
                        "type": "value_error",
                        "loc": (field_name,),
                        "ctx": {"error": "Input must be a list or a dictionary"},
                    }
                ],
            )

    def iter(self) -> Iterator[Request]:
        yield from self.secret
        yield from self.secrets


class LocalConfig(BaseModel):
    """Data model that represents a local configuration file."""

    providers: dict[str | None, Provider] = Field(default_factory=dict)
    requests: list[Request] = Field(default_factory=list)

    @model_validator(mode="before")
    @classmethod
    def _before_validator(cls, values):
        if isinstance(values, dict):
            errors = []
            with capture_line_errors(errors, ()):
                builder = ProviderBuilder.model_validate(values)
                values["providers"] = builder.collect()
            with capture_line_errors(errors, ()):
                builder = RequestBuilder.model_validate(values)
                values["requests"] = builder.iter()
            if errors:
                raise ValidationError.from_exception_data(
                    title="local config", line_errors=errors
                )
        return values


@contextlib.contextmanager
def capture_line_errors(line_errors: list[ErrorDetails], prefix: Sequence[str | int]):
    try:
        yield
    except ValidationError as e:
        for err in e.errors():
            err = err.copy()
            err["loc"] = (*prefix, *err["loc"])
            line_errors.append(err)
