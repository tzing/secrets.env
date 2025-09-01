from __future__ import annotations

import contextlib
import typing

from pydantic import BaseModel, Field, ValidationError, field_validator, model_validator

from secrets_env.provider import AsyncProvider, Provider, Request
from secrets_env.providers import get_provider

if typing.TYPE_CHECKING:
    from collections.abc import Sequence
    from typing import Self

    from pydantic import ValidationInfo
    from pydantic_core import ErrorDetails


class LocalConfig(BaseModel):
    """Data model that represents a local configuration file."""

    sources: list[Provider | AsyncProvider] = Field(default_factory=list)
    secrets: list[Request] = Field(default_factory=list)

    @model_validator(mode="before")
    @classmethod
    def _before_validator_(cls, values):
        if isinstance(values, dict):
            errors = []

            with capture_line_errors(errors, ()):
                providers = ProviderBuilder.model_validate(values)
                values["sources"] = providers.source + providers.sources
            with capture_line_errors(errors, ()):
                requests = RequestBuilder.model_validate(values)
                values["secrets"] = requests.secret + requests.secrets

            if errors:
                raise ValidationError.from_exception_data(
                    title="local config", line_errors=errors
                )

        return values

    @model_validator(mode="after")
    def _check_source_exists_(self) -> Self:
        # collect available source names
        available_sources = {provider.name for provider in self.sources}
        has_default_source = len(self.sources) == 1

        # ensure all requests have a valid source
        errors = []
        for request in self.secrets:
            if request.source in available_sources:
                continue  # valid
            if request.source is None and has_default_source:
                continue  # use default

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

        # raise errors
        if errors:
            raise ValidationError.from_exception_data(
                title="local config", line_errors=errors
            )

        return self

    # TODO remove below; they are setup for backward compatibility

    @property
    def requests(self) -> list[Request]:
        return self.secrets

    @property
    def providers(self):
        # FIXME known defect
        return {provider.name: provider for provider in self.sources}


class ProviderBuilder(BaseModel):
    """Internal helper to build provider instances from source(s) configs."""

    source: list[Provider | AsyncProvider] = Field(default_factory=list)
    sources: list[Provider | AsyncProvider] = Field(default_factory=list)

    @field_validator("source", "sources", mode="before")
    @classmethod
    def _transform_(cls, value, info: ValidationInfo):
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
                    title=typing.cast("str", info.field_name), line_errors=errors
                )
            return providers

        raise ValueError("Input must be a list or a dictionary")

    @model_validator(mode="after")
    def _check_dupe_name_(self) -> Self:
        seen_names = {}
        for idx, provider in enumerate(self.source):
            seen_names.setdefault(provider.name, []).append(("source", idx))
        for idx, provider in enumerate(self.sources):
            seen_names.setdefault(provider.name, []).append(("sources", idx))

        errors = []
        for name, locations in seen_names.items():
            if len(locations) == 1:
                continue
            for loc in locations:
                errors.append(
                    {
                        "type": "value_error",
                        "loc": (*loc, "name"),
                        "input": name,
                        "ctx": {"error": "duplicated provider name"},
                    }
                )

        if errors:
            raise ValidationError.from_exception_data(
                title="sources", line_errors=errors
            )

        return self


class RequestBuilder(BaseModel):
    """Internal helper to build request instances from secret(s) configs."""

    secret: list[Request] = Field(default_factory=list)
    secrets: list[Request] = Field(default_factory=list)

    @field_validator("secret", "secrets", mode="before")
    @classmethod
    def _transform_(cls, value: list | dict[str, dict | str], info: ValidationInfo):
        if isinstance(value, list):
            return value

        if isinstance(value, dict):
            requests = []
            errors = []
            for name, spec in value.items():
                with capture_line_errors(errors, (name,)):
                    if isinstance(spec, dict):
                        spec = spec.copy()
                        spec["name"] = name
                        requests.append(Request(**spec))
                    elif isinstance(spec, str):
                        requests.append(Request(name=name, value=spec))
                    else:
                        requests.append(spec)

            if errors:
                raise ValidationError.from_exception_data(
                    title=typing.cast("str", info.field_name), line_errors=errors
                )
            return requests

        # type error here does not get caught by pydantic
        raise ValueError(f'expect list or dict for "{info.field_name}"')

    @model_validator(mode="after")
    def _check_dupe_name_(self) -> Self:
        seen_names = {}
        for idx, request in enumerate(self.secret):
            seen_names.setdefault(request.name, []).append(("secret", idx))
        for idx, request in enumerate(self.secrets):
            seen_names.setdefault(request.name, []).append(("secrets", idx))

        errors = []
        for name, locations in seen_names.items():
            if len(locations) == 1:
                continue
            for loc in locations:
                errors.append(
                    {
                        "type": "value_error",
                        "loc": (*loc, "name"),
                        "input": name,
                        "ctx": {"error": "duplicated secret name"},
                    }
                )

        if errors:
            raise ValidationError.from_exception_data(
                title="secrets", line_errors=errors
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
