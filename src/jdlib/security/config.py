"""Strongly typed security configuration with secure defaults (spec #31-#33).

Design rules:

* every default favours security (spec #32),
* unsafe combinations are unrepresentable: the model validates on
  construction, so ``production`` + disabled authentication (or any other
  insecure posture) raises :class:`SecurityConfigurationError` at startup
  instead of failing open at runtime,
* there is no option that enables secret logging or raw token logging — such
  knobs are deliberately absent from the schema, and a test locks the schema
  so adding one requires an explicit, reviewed change,
* configuration is immutable once built: security posture cannot be mutated
  from underneath a running request (spec #92, "no global mutable security
  state").

Outbound transport settings (TLS verification, certificate verification,
retry and circuit-breaker policy) live with the HTTP adapters that use them
(phases 2-4), not here, so the core configuration stays free of vendor
concerns.
"""

from __future__ import annotations

from datetime import timedelta
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, SecretStr, model_validator

from jdlib.security.errors import SecurityConfigurationError

MINIMUM_SIGNING_KEY_BYTES = 32
MAXIMUM_PRODUCTION_AUTHORIZATION_TIMEOUT = timedelta(seconds=10)


class Environment(StrEnum):
    """Deployment environment governing the required security posture."""

    DEVELOPMENT = "development"
    TEST = "test"
    STAGING = "staging"
    PRODUCTION = "production"


class _SecurityModel(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class AuthenticationConfig(_SecurityModel):
    """Inbound authentication posture."""

    enabled: bool = True
    require_authentication: bool = True


class AuthorizationConfig(_SecurityModel):
    """Authorization (PEP/PDP) posture."""

    enabled: bool = True
    require_authorization: bool = True
    fail_closed: bool = True
    allow_all: bool = False
    timeout: timedelta = timedelta(seconds=2)


class TenantSecurityConfig(_SecurityModel):
    """Tenancy and data-boundary posture."""

    require_tenant_context: bool = True
    trust_tenant_header: bool = False
    allow_privileged_bypass: bool = False


class GatewayConfig(_SecurityModel):
    """Trust model for identity information arriving from an API gateway."""

    trust_identity_headers: bool = False
    require_identity_envelope: bool = True


class AuditConfig(_SecurityModel):
    """Audit posture."""

    enabled: bool = True


class ObservabilityConfig(_SecurityModel):
    """Observability posture."""

    debug_security_errors: bool = False
    trace_propagation: bool = True


class ComplianceConfig(_SecurityModel):
    """Deployment profile used for posture validation."""

    environment: Environment = Environment.DEVELOPMENT


class SecurityConfig(_SecurityModel):
    """Complete security configuration; validated on construction."""

    authentication: AuthenticationConfig = AuthenticationConfig()
    authorization: AuthorizationConfig = AuthorizationConfig()
    tenancy: TenantSecurityConfig = TenantSecurityConfig()
    gateway: GatewayConfig = GatewayConfig()
    audit: AuditConfig = AuditConfig()
    observability: ObservabilityConfig = ObservabilityConfig()
    compliance: ComplianceConfig = ComplianceConfig()

    @model_validator(mode="after")
    def _validate_posture(self) -> SecurityConfig:
        validate_security_config(self)
        return self


def validate_security_config(config: SecurityConfig) -> None:
    """Validate a security configuration, raising on any unsafe combination.

    Construction already validates; this entry point exists so applications can
    re-check configurations that were assembled with ``model_construct`` or
    loaded from an external source, and fail startup before serving traffic.
    """
    authentication = config.authentication
    authorization = config.authorization
    tenancy = config.tenancy
    gateway = config.gateway

    if gateway.trust_identity_headers and not gateway.require_identity_envelope:
        raise SecurityConfigurationError(
            "trusting gateway identity headers without a signed identity envelope "
            "is not permitted: identity headers would be forgeable"
        )
    if authorization.timeout <= timedelta(0):
        raise SecurityConfigurationError(
            "authorization timeout must be positive: an unbounded authorization "
            "call would block the request pipeline"
        )

    if config.compliance.environment is not Environment.PRODUCTION:
        return

    if authorization.timeout > MAXIMUM_PRODUCTION_AUTHORIZATION_TIMEOUT:
        raise SecurityConfigurationError(
            "authorization timeout must be at most "
            f"{MAXIMUM_PRODUCTION_AUTHORIZATION_TIMEOUT.total_seconds():g}s in production"
        )
    if not authentication.enabled:
        raise SecurityConfigurationError(
            "authentication cannot be disabled in production"
        )
    if not authentication.require_authentication:
        raise SecurityConfigurationError(
            "authentication cannot be optional in production"
        )
    if not authorization.enabled:
        raise SecurityConfigurationError("authorization cannot be disabled in production")
    if not authorization.require_authorization:
        raise SecurityConfigurationError("authorization cannot be optional in production")
    if authorization.allow_all:
        raise SecurityConfigurationError(
            "allow-all authorization is not permitted in production"
        )
    if not authorization.fail_closed:
        raise SecurityConfigurationError(
            "authorization must fail closed in production"
        )
    if tenancy.trust_tenant_header:
        raise SecurityConfigurationError(
            "trusting tenant headers is not permitted in production"
        )
    if tenancy.allow_privileged_bypass:
        raise SecurityConfigurationError(
            "privileged bypass must be disabled in production"
        )
    if gateway.trust_identity_headers:
        raise SecurityConfigurationError(
            "gateway identity headers cannot be trusted in production"
        )
    if not config.audit.enabled:
        raise SecurityConfigurationError(
            "audit cannot be disabled in production: security evidence would be lost"
        )
    if config.observability.debug_security_errors:
        raise SecurityConfigurationError(
            "debug security errors must be disabled in production"
        )


def assert_strong_signing_key(
    key: SecretStr | str, *, minimum_bytes: int = MINIMUM_SIGNING_KEY_BYTES
) -> None:
    """Fail closed when an HMAC signing key is blank or too short.

    The error never includes the key material; only the required and observed
    length, which is not sensitive.
    """
    raw = key.get_secret_value() if isinstance(key, SecretStr) else key
    if not raw.strip():
        raise SecurityConfigurationError("signing key must not be blank")
    length = len(raw.encode())
    if length < minimum_bytes:
        raise SecurityConfigurationError(
            f"signing key must be at least {minimum_bytes} bytes (got {length})"
        )


__all__ = [
    "AuditConfig",
    "AuthenticationConfig",
    "AuthorizationConfig",
    "ComplianceConfig",
    "Environment",
    "GatewayConfig",
    "MAXIMUM_PRODUCTION_AUTHORIZATION_TIMEOUT",
    "MINIMUM_SIGNING_KEY_BYTES",
    "ObservabilityConfig",
    "SecurityConfig",
    "TenantSecurityConfig",
    "assert_strong_signing_key",
    "validate_security_config",
]
