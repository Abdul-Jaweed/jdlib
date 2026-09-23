"""Phase 1 security core: strongly typed security configuration.

Spec refs: #31 (configuration security), #32 (secure defaults), #33 (production
safety posture), #62 (configuration validation), #78 (timeouts), #92 (forbidden
shortcuts).
"""

from __future__ import annotations

from datetime import timedelta

import pytest
from pydantic import ValidationError

from jdlib.security.config import (
    AuditConfig,
    AuthenticationConfig,
    AuthorizationConfig,
    ComplianceConfig,
    Environment,
    GatewayConfig,
    ObservabilityConfig,
    SecurityConfig,
    TenantSecurityConfig,
    assert_strong_signing_key,
    validate_security_config,
)
from jdlib.security.errors import SecurityCode, SecurityConfigurationError, security_code

PRODUCTION = {"compliance": {"environment": "production"}}


def _production(**sections: object) -> SecurityConfig:
    payload: dict[str, object] = dict(PRODUCTION)
    payload.update(sections)
    return SecurityConfig.model_validate(payload)


# --- Secure defaults --------------------------------------------------------


def test_defaults_are_secure() -> None:
    config = SecurityConfig()
    assert config.authentication.enabled is True
    assert config.authentication.require_authentication is True
    assert config.authorization.enabled is True
    assert config.authorization.require_authorization is True
    assert config.authorization.fail_closed is True
    assert config.authorization.allow_all is False
    assert config.tenancy.require_tenant_context is True
    assert config.tenancy.trust_tenant_header is False
    assert config.tenancy.allow_privileged_bypass is False
    assert config.gateway.trust_identity_headers is False
    assert config.gateway.require_identity_envelope is True
    assert config.audit.enabled is True
    assert config.observability.debug_security_errors is False
    assert config.compliance.environment is Environment.DEVELOPMENT


def test_secure_defaults_are_valid_in_production() -> None:
    validate_security_config(_production())


def test_config_is_immutable_once_built() -> None:
    config = _production()
    with pytest.raises(ValidationError):
        config.authorization.allow_all = True  # type: ignore[misc]
    with pytest.raises(ValidationError):
        config.compliance.environment = Environment.DEVELOPMENT  # type: ignore[misc]


def test_no_configuration_option_can_enable_secret_logging() -> None:
    # Any new field must be a deliberate schema change: secret logging, token
    # logging and header dumps stay unrepresentable in configuration.
    assert set(AuthenticationConfig.model_fields) == {"enabled", "require_authentication"}
    assert set(AuthorizationConfig.model_fields) == {
        "enabled",
        "require_authorization",
        "fail_closed",
        "allow_all",
        "timeout",
    }
    assert set(TenantSecurityConfig.model_fields) == {
        "require_tenant_context",
        "trust_tenant_header",
        "allow_privileged_bypass",
    }
    assert set(GatewayConfig.model_fields) == {
        "trust_identity_headers",
        "require_identity_envelope",
    }
    assert set(AuditConfig.model_fields) == {"enabled"}
    assert set(ObservabilityConfig.model_fields) == {
        "debug_security_errors",
        "trace_propagation",
    }
    assert set(ComplianceConfig.model_fields) == {"environment"}


# --- Production posture -----------------------------------------------------


@pytest.mark.parametrize(
    ("section", "payload"),
    [
        ("authentication", {"enabled": False}),
        ("authentication", {"require_authentication": False}),
        ("authorization", {"enabled": False}),
        ("authorization", {"require_authorization": False}),
        ("authorization", {"allow_all": True}),
        ("authorization", {"fail_closed": False}),
        ("tenancy", {"trust_tenant_header": True}),
        ("tenancy", {"allow_privileged_bypass": True}),
        ("gateway", {"trust_identity_headers": True}),
        ("audit", {"enabled": False}),
        ("observability", {"debug_security_errors": True}),
    ],
)
def test_production_rejects_unsafe_configuration(
    section: str, payload: dict[str, object]
) -> None:
    with pytest.raises(SecurityConfigurationError) as excinfo:
        _production(**{section: payload})
    assert security_code(excinfo.value) is SecurityCode.SECURITY_CONFIGURATION_ERROR
    assert "production" in str(excinfo.value)


def test_development_stays_workable() -> None:
    config = SecurityConfig.model_validate(
        {
            "observability": {"debug_security_errors": True},
            "audit": {"enabled": False},
            "compliance": {"environment": "development"},
        }
    )
    validate_security_config(config)


def test_unsigned_gateway_identity_is_rejected_in_every_environment() -> None:
    for environment in ("development", "test", "staging", "production"):
        with pytest.raises(SecurityConfigurationError):
            SecurityConfig.model_validate(
                {
                    "gateway": {
                        "trust_identity_headers": True,
                        "require_identity_envelope": False,
                    },
                    "compliance": {"environment": environment},
                }
            )


def test_explicit_validation_catches_configs_that_bypassed_constructors() -> None:
    config = SecurityConfig.model_construct(
        authentication=AuthenticationConfig.model_construct(enabled=False),
        authorization=AuthorizationConfig(),
        tenancy=TenantSecurityConfig(),
        gateway=GatewayConfig(),
        audit=AuditConfig(),
        observability=ObservabilityConfig(),
        compliance=ComplianceConfig(environment=Environment.PRODUCTION),
    )
    with pytest.raises(SecurityConfigurationError):
        validate_security_config(config)


# --- Timeouts ---------------------------------------------------------------


@pytest.mark.parametrize("timeout", [timedelta(0), timedelta(seconds=-1)])
def test_authorization_timeout_must_be_positive(timeout: timedelta) -> None:
    with pytest.raises(SecurityConfigurationError):
        SecurityConfig.model_validate({"authorization": {"timeout": timeout}})


def test_production_bounds_authorization_timeout() -> None:
    with pytest.raises(SecurityConfigurationError):
        _production(authorization={"timeout": timedelta(seconds=60)})
    validate_security_config(_production(authorization={"timeout": timedelta(seconds=2)}))


# --- Signing key strength ---------------------------------------------------


def test_strong_signing_key_accepts_32_bytes() -> None:
    assert_strong_signing_key("k" * 32)


@pytest.mark.parametrize("key", ["", "short", "k" * 31])
def test_weak_signing_key_is_rejected(key: str) -> None:
    with pytest.raises(SecurityConfigurationError):
        assert_strong_signing_key(key)


def test_signing_key_error_never_leaks_the_key() -> None:
    secret = "sup3r-s3cret-key-material-do-not-log"
    with pytest.raises(SecurityConfigurationError) as excinfo:
        assert_strong_signing_key(secret, minimum_bytes=512)
    rendered = f"{excinfo.value!r} {excinfo.value}"
    assert secret not in rendered
