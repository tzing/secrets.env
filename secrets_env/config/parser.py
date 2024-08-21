from __future__ import annotations

import contextlib
import itertools
from typing import TYPE_CHECKING, cast

from pydantic import BaseModel, Field, ValidationError, field_validator, model_validator

from secrets_env.provider import Provider, Request
from secrets_env.providers import get_provider

if TYPE_CHECKING:
    from typing import Iterator, Sequence

    from pydantic import ValidationInfo
    from pydantic_core import ErrorDetails


class _ProviderAdapter(BaseModel):
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

    def to_dict(self) -> dict[str, Provider]:
        """
        Returns an iterator of tuples with the provider name and the provider instance.

        Raises
        ------
        ValidationError
            If the source names are not unique.
        """
        providers = {}
        errors = []

        for provider in itertools.chain(self.source, self.sources):
            if provider.name in providers:
                errors.append(
                    {
                        "type": "value_error",
                        "loc": ("sources", "*", "name"),
                        "input": provider.name or "(anonymous)",
                        "ctx": {"error": "duplicated source name"},
                    }
                )
            else:
                providers[provider.name] = provider

        if None in providers and len(providers) > 1:
            errors.append(
                {
                    "type": "value_error",
                    "loc": ("sources", "*", "name"),
                    "ctx": {
                        "error": "naming each source is mandatory when using multiple sources",
                    },
                }
            )

        if errors:
            raise ValidationError.from_exception_data(
                title="sources", line_errors=errors
            )

        return providers


def validate_providers(values):
    """Build source(s) configs into provider instances."""
    if isinstance(values, dict):
        adapter = _ProviderAdapter.model_validate(values)
        providers = values.setdefault("providers", {})
        providers.update(adapter.to_dict())
    return values


class ProviderAdapter(BaseModel):

    providers: dict[str | None, Provider] = Field(default_factory=dict)

    @classmethod
    def before_validator(cls, values):
        if isinstance(values, dict):
            adapter = _ProviderAdapter.model_validate(values)
            providers = values.setdefault("providers", {})
            providers.update(adapter.to_dict())
        return values

    @model_validator(mode="before")
    def _before_validator(cls, values):
        return cls.before_validator(values)


class _RequestAdapter(BaseModel):
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
            # type error here does not get caught by pydantic
            raise ValueError(f'expect list or dict for "{info.field_name}"')

    def iter_requests(self) -> Iterator[Request]:
        seen_names = set()
        errors = []

        for request in itertools.chain(self.secret, self.secrets):
            if request.name in seen_names:
                errors.append(
                    {
                        "type": "value_error",
                        "loc": ("secrets", request.name),
                        "input": request.name,
                        "ctx": {"error": "duplicated secret name"},
                    }
                )

            else:
                seen_names.add(request.name)
                yield request

        if errors:
            raise ValidationError.from_exception_data(
                title="secrets", line_errors=errors
            )


class RequestAdapter(BaseModel):
    """Build secret(s) configs into request instances."""

    requests: list[Request] = Field(default_factory=dict)

    @classmethod
    def before_validator(cls, values):
        if isinstance(values, dict):
            adapter = _RequestAdapter.model_validate(values)
            requests = values.setdefault("requests", [])
            requests.extend(adapter.iter_requests())
        return values

    @model_validator(mode="before")
    @classmethod
    def _before_validator(cls, values):
        return cls.before_validator(values)


class LocalConfig(ProviderAdapter, RequestAdapter):
    """Data model that represents a local configuration file."""

    @model_validator(mode="before")
    @classmethod
    def _before_validator(cls, values):
        errors = []
        with capture_line_errors(errors, ()):
            values = ProviderAdapter.before_validator(values)
        with capture_line_errors(errors, ()):
            values = RequestAdapter.before_validator(values)
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
