from __future__ import annotations

import contextlib
import itertools
from typing import TYPE_CHECKING, cast

from pydantic import BaseModel, Field, ValidationError, field_validator, model_validator

from secrets_env.provider import Provider, Request
from secrets_env.providers import get_provider

if TYPE_CHECKING:
    from typing import Iterator, Sequence, TypeVar

    from pydantic import ValidationInfo
    from pydantic_core import ErrorDetails

    _T = TypeVar("_T")


class _ProviderBuilder(BaseModel):
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
                        "input": provider.name,
                        "ctx": {"error": "duplicated source name"},
                    }
                )
            else:
                providers[provider.name] = provider

        if errors:
            raise ValidationError.from_exception_data(
                title="sources", line_errors=errors
            )

        return providers


def validate_providers(values: _T) -> _T:
    """
    Build source(s) configs into provider instances.
    This function is intended to be used as a before validator for Pydantic models
    with the attribute ``providers`` of type ``dict[str, Provider]``.
    """
    if isinstance(values, dict):
        adapter = _ProviderBuilder.model_validate(values)
        providers = values.setdefault("providers", {})
        providers.update(adapter.to_dict())
    return values


class _RequestBuilder(BaseModel):
    """Internal helper to build request instances from secret(s) configs."""

    secret: list[Request] = Field(default_factory=list)
    secrets: list[Request] = Field(default_factory=list)

    @field_validator("secret", "secrets", mode="before")
    @classmethod
    def _transform(cls, value: list | dict[str, dict | str], info: ValidationInfo):
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
                    title=cast(str, info.field_name), line_errors=errors
                )
            return requests

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


def validate_requests(values: _T) -> _T:
    """
    Build secret(s) configs into request instances.

    This function is intended to be used as a before validator for Pydantic models
    with the attribute ``requests`` of type ``list[Request]``.
    """
    if isinstance(values, dict):
        adapter = _RequestBuilder.model_validate(values)
        requests = values.setdefault("requests", [])
        requests.extend(adapter.iter_requests())
    return values


class LocalConfig(BaseModel):
    """Data model that represents a local configuration file."""

    providers: dict[str | None, Provider] = Field(default_factory=dict)
    requests: list[Request] = Field(default_factory=dict)

    @model_validator(mode="before")
    @classmethod
    def _before_validator(cls, values):
        errors = []
        with capture_line_errors(errors, ()):
            values = validate_providers(values)
        with capture_line_errors(errors, ()):
            values = validate_requests(values)
        if errors:
            raise ValidationError.from_exception_data(
                title="local config", line_errors=errors
            )
        return values

    @model_validator(mode="after")
    def _check_source_exists(self):
        # if there is only one source, it will be used as the default source
        default_source = None
        if len(self.providers) == 1:
            default_source = next(iter(self.providers))

        # check if all requests have a valid source
        errors = []
        for request in self.requests:
            applied_source = request.source or default_source
            if applied_source not in self.providers:
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
