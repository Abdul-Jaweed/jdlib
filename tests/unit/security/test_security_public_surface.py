"""Phase 1 security core: public surface and import safety.

Spec refs: #72 (deliberate public API, avoid unnecessary exports), #74 (core
import must stay lightweight), #58 (existing public APIs remain compatible).
"""

from __future__ import annotations

import json
import subprocess
import sys

import jdlib
import jdlib.security as security

EXPECTED_SURFACE = frozenset(
    {
        # context
        "AuthMethod",
        "RequestIds",
        "SecurityContext",
        "TokenMetadata",
        "current_security_context",
        "current_security_context_or_none",
        "new_request_ids",
        "security_context_scope",
        # configuration
        "AuditConfig",
        "AuthenticationConfig",
        "AuthorizationConfig",
        "ComplianceConfig",
        "Environment",
        "GatewayConfig",
        "ObservabilityConfig",
        "SecurityConfig",
        "TenantSecurityConfig",
        "assert_strong_signing_key",
        "validate_security_config",
        # errors
        "SecurityClassification",
        "SecurityCode",
        "SecurityConfigurationError",
        "SecurityDescriptor",
        "describe_error",
        "is_retryable",
        "security_code",
        "www_authenticate",
        # interfaces
        "GatewayAdapter",
        "GatewayIdentity",
        "OutboundToken",
        "RateLimitDecision",
        "RateLimiter",
        "TokenProvider",
        "TokenValidator",
        "ValidatedToken",
    }
)

OPTIONAL_DISTRIBUTIONS = ("fastapi", "pytest", "typer", "cerbos", "opentelemetry", "httpx")


def test_security_surface_is_exactly_the_documented_api() -> None:
    assert frozenset(security.__all__) == EXPECTED_SURFACE
    assert len(security.__all__) == len(EXPECTED_SURFACE)


def test_every_exported_security_name_resolves() -> None:
    for name in security.__all__:
        assert getattr(security, name) is not None


def test_security_import_does_not_pull_optional_dependencies() -> None:
    script = (
        "import json, sys, jdlib.security; "
        f"loaded = sorted({{name.split('.')[0] for name in sys.modules}} "
        f"& set({OPTIONAL_DISTRIBUTIONS!r})); "
        "print(json.dumps(loaded))"
    )
    result = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        check=True,
    )
    assert json.loads(result.stdout) == []


def test_core_public_api_is_unchanged() -> None:
    # Phase 1 adds a namespace, it does not alter the existing one (#58).
    assert "SecurityConfig" not in jdlib.__all__
    for name in jdlib.__all__:
        assert getattr(jdlib, name) is not None


AUTHN_SURFACE = frozenset(
    {
        "ASYMMETRIC_ALGORITHMS",
        "ClientAuthMethod",
        "ClientCredentialsConfig",
        "ClientCredentialsTokenProvider",
        "JwksFetch",
        "JwtClaimMapping",
        "JwtTokenValidator",
        "SigningKeySource",
        "TokenAcquisitionError",
        "TokenEndpointUnavailable",
        "TokenFetch",
        "ZitadelConfig",
        "assert_safe_algorithms",
        "build_zitadel_token_provider",
        "build_zitadel_token_validator",
        "zitadel_provider_config",
    }
)


def test_authn_surface_is_exactly_the_documented_api() -> None:
    from jdlib.security import authn

    assert frozenset(authn.__all__) == AUTHN_SURFACE
    for name in authn.__all__:
        assert getattr(authn, name) is not None


def test_authn_import_does_not_pull_optional_dependencies() -> None:
    script = (
        "import json, sys, jdlib.security.authn; "
        f"loaded = sorted({{name.split('.')[0] for name in sys.modules}} "
        f"& set({OPTIONAL_DISTRIBUTIONS!r})); "
        "print(json.dumps(loaded))"
    )
    result = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        check=True,
    )
    assert json.loads(result.stdout) == []
