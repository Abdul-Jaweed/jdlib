from __future__ import annotations

from datetime import timedelta
from enum import StrEnum

from pydantic import BaseModel, SecretStr, field_validator
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

    @field_validator("path_prefix")
    @classmethod
    def _path_prefix_must_be_absolute(cls, value: str) -> str:
        if not value or not value.startswith("/"):
            raise ValueError("path_prefix must be a non-empty path starting with '/'")
        return value


class OidcConfig(BaseModel):
    issuer: str
    audience: str
    algorithms: list[str] = ["RS256"]
    jwks_url: str | None = None
    jwks_ttl: timedelta = timedelta(hours=1)
    leeway: timedelta = timedelta(seconds=60)
    email_trusted: bool = False

    def resolved_jwks_url(self) -> str:
        if self.jwks_url:
            return self.jwks_url
        return self.issuer.rstrip("/") + "/.well-known/jwks.json"


class ApiKeyConfig(BaseModel):
    prefix: str = "jd"


class RlsConfig(BaseModel):
    enabled: bool = False
    app_role: str | None = None


class TenancyConfig(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="JDLIB_", env_nested_delimiter="__")

    control_dsn: SecretStr | None = None
    context: ContextConfig
    resolvers: ResolverConfig = ResolverConfig()
    oidc: OidcConfig | None = None
    api_keys: ApiKeyConfig = ApiKeyConfig()
    rls: RlsConfig = RlsConfig()
