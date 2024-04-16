from __future__ import annotations

import contextlib
from typing import TYPE_CHECKING, cast

from pydantic import BaseModel, Field, ValidationError, field_validator, model_validator

from secrets_env.provider import Provider, Request
from secrets_env.providers import get_provider

if TYPE_CHECKING:
    from typing import Iterator, Sequence

    from pydantic import ValidationInfo
    from pydantic_core import ErrorDetails


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
            providers = []
            errors = []
            for i, item in enumerate(value):
                with capture_line_errors(errors, (i,)):
                    if isinstance(item, dict):
                        providers.append(get_provider(item))
                    else:
                        providers.append(item)

            if errors:
                raise ValidationError.from_exception_data(
                    title=cast(str, info.field_name), line_errors=errors
                )
            return providers

        else:
            raise ValueError("Input must be a list or a dictionary")

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
                        "error": "Naming each source is mandatory when using multiple sources",
                    },
                }
            )

        if errors:
            raise ValidationError.from_exception_data(
                title="sources", line_errors=errors
            )

        return providers


class RequestBuilder(BaseModel):
    """Internal helper to build request instances from secret(s) configs."""

    secret: list[Request] = Field(default_factory=list)
    secrets: list[Request] = Field(default_factory=list)

    @field_validator("secret", "secrets", mode="before")
    @classmethod
    def _transform(cls, value: list | dict[str, dict | str], info: ValidationInfo):
        if isinstance(value, list):
            return value

        elif isinstance(value, dict):
            requests = []
            errors = []
            for name, spec in value.items():
                with capture_line_errors(errors, (name,)):
                    if isinstance(spec, dict):
                        requests.append(Request(name=name, **spec))
                    elif isinstance(spec, str):
                        requests.append(Request(name=name, value=spec))
                    else:
                        requests.append(spec)

            if errors:
                raise ValidationError.from_exception_data(
                    title=cast(str, info.field_name), line_errors=errors
                )
            return requests

        else:
            raise ValueError("Input must be a list or a dictionary")

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

    @model_validator(mode="after")
    def _check_source_exists(self):
        errors = []
        for request in self.requests:
            if request.source not in self.providers:
                if request.source is None:
                    errors.append(
                        {
                            "type": "missing",
                            "loc": ("secrets", request.name, "source"),
                        }
                    )
                else:
                    errors.append(
                        {
                            "type": "value_error",
                            "loc": ("secrets", request.name, "source"),
                            "input": request.source,
                            "ctx": {"error": f'source "{request.source}" not found'},
                        }
                    )
        if errors:
            raise ValidationError.from_exception_data(
                title="local config", line_errors=errors
            )
        return self


@contextlib.contextmanager
def capture_line_errors(line_errors: list[ErrorDetails], prefix: Sequence[str | int]):
    try:
        yield
    except ValidationError as e:
        for err in e.errors():
            err = err.copy()
            if err["type"] == "path_not_file":
                # workaround; `path_not_file` is raised by Pydantic's PathType
                # but this type is not acceptable by `from_exception_data`
                err["type"] = "value_error"
                err["ctx"] = {"error": err["msg"]}
            err["loc"] = (*prefix, *err["loc"])
            line_errors.append(err)
