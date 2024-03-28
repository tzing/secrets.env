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
        if isinstance(value, dict):
            value = [value]

        if isinstance(value, list):
            field_name = cast(str, info.field_name)
            errors = []
            for i, item in enumerate(value):
                with capture_line_errors(errors, (field_name, i)):
                    if isinstance(item, dict):
                        yield get_provider(item)
                    else:
                        yield item
            if errors:
                raise ValidationError.from_exception_data(
                    title="sources", line_errors=errors
                )

        else:
            raise TypeError("Input must be a list or a dictionary")

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
        if isinstance(value, list):
            yield from value

        elif isinstance(value, dict):
            field_name = cast(str, info.field_name)
            errors = []
            for name, spec in value.items():
                with capture_line_errors(errors, (field_name, name)):
                    if isinstance(spec, dict):
                        yield Request(name=name, **spec)
                    else:
                        yield Request(name=name, value=spec)
            if errors:
                raise ValidationError.from_exception_data(
                    title=field_name, line_errors=errors
                )

        else:
            raise TypeError("Input must be a list or a dictionary")

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
            providers = ProviderBuilder.model_validate(values)
            requests = RequestBuilder.model_validate(values)
            values["providers"] = providers.collect()
            values["requests"] = requests.iter()
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
