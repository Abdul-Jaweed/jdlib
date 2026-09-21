from __future__ import annotations

from datetime import timedelta
from enum import StrEnum

from pydantic import BaseModel, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class ResolverName(StrEnum):
    JWT_CLAIM = "jwt_claim"
    SUBDOMAIN = "subdomain"
    PATH = "path"
    HEADER = "header"
    API_KEY = "api_key"


class ContextConfig(BaseModel):
    signing_key: SecretStr
    envelope_ttl: timedelta = timedelta(minutes=5)
    operator_ttl: timedelta = timedelta(minutes=30)
    allow_test_contexts: bool = False


class ResolverConfig(BaseModel):
    order: list[ResolverName] = [
        ResolverName.JWT_CLAIM,
        ResolverName.SUBDOMAIN,
        ResolverName.PATH,
        ResolverName.HEADER,
        ResolverName.API_KEY,
    ]
    base_domain: str | None = None
    path_prefix: str = "/t/"
    header_name: str = "X-Tenant-Slug"
    jwt_claim: str = "tid"


class TenancyConfig(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="JDLIB_", env_nested_delimiter="__")

    control_dsn: SecretStr | None = None
    context: ContextConfig
    resolvers: ResolverConfig = ResolverConfig()
