from __future__ import annotations

from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, Field, ValidationError, field_validator, model_validator

from secrets_env.provider import Provider, RequestSpec
from secrets_env.providers import get_provider

if TYPE_CHECKING:
    from typing import Iterator


class ProviderBuilder(BaseModel):
    """Internal helper to build provider instances from source(s) configs."""

    source: list[dict[str, Any]] = Field(default_factory=list)
    sources: list[dict[str, Any]] = Field(default_factory=list)

    @field_validator("source", "sources", mode="before")
    @classmethod
    def _accept_dict(cls, value):
        if isinstance(value, dict):
            return [value]
        return value

    def __iter__(self) -> Iterator[Provider]:
        """
        Returns an iterator of provider instances based on the configuration.

        Raises
        ------
        ValidationError
            If the provider configuration is invalid.
        """
        errors = []

        def to_provider(loc: str, data: list[dict]) -> Iterator[Provider]:
            nonlocal errors
            for i, item in enumerate(data):
                try:
                    yield get_provider(item)
                except ValidationError as e:
                    for err in e.errors():
                        err["loc"] = (loc, i, *err["loc"])
                        errors.append(err)

        yield from to_provider("source", self.source or [])
        yield from to_provider("sources", self.sources or [])

        if errors:
            raise ValidationError.from_exception_data(
                title="sources", line_errors=errors
            )

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

        for provider in self:
            if provider.name in providers:
                errors.append(
                    {
                        "type": "value_error",
                        "loc": ("sources", "*", "name"),
                        "input": provider.name or "(anonymous)",
                        "ctx": {
                            "error": "duplicate source name",
                        },
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
    spec: RequestSpec

    @field_validator("name", mode="after")
    @classmethod
    def _check_name_format(cls, value: str):
        if not re.fullmatch(r"[a-zA-Z_]\w*", value):
            raise ValueError("Invalid environment variable name")
        return value


class LocalConfig(BaseModel):
    """
    Data model that represents a local configuration file.
    """

    providers: dict[str, Provider] = Field(default_factory=dict)
    secrets: dict[str, RequestSpec] = Field(default_factory=dict)

    @model_validator(mode="before")
    @classmethod
    def _before_validator(cls, values):
        if isinstance(values, dict):
            # create providers
            builder = ProviderBuilder.model_validate(values)
            values["providers"] = builder.collect()

            # allow 'secret' keyword
            secrets = values.pop("secret", {})
            secrets.update(values.pop("secrets", {}))
            values["secrets"] = secrets

        return values
