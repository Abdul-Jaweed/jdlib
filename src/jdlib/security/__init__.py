"""Security core: context, configuration, errors and interfaces (spec #72).

This package is the deliberate public surface of the security foundation:

* :mod:`jdlib.security.context` — ``SecurityContext``, request identities,
  ``contextvars`` binding,
* :mod:`jdlib.security.config` — strongly typed, secure-by-default
  configuration with fail-fast posture validation,
* :mod:`jdlib.security.errors` — stable machine-readable security error
  codes and descriptors,
* :mod:`jdlib.security.interfaces` — ports for authentication, gateway and
  rate-limiting adapters.

Import safety (spec #74): depends only on the standard library, pydantic and
the existing ``jdlib`` core. No optional dependency is imported here.
"""

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
from jdlib.security.context import (
    AuthMethod,
    RequestIds,
    SecurityContext,
    TokenMetadata,
    current_security_context,
    current_security_context_or_none,
    new_request_ids,
    security_context_scope,
)
from jdlib.security.errors import (
    AuthorizationUnavailable,
    SecurityClassification,
    SecurityCode,
    SecurityConfigurationError,
    SecurityDescriptor,
    describe_error,
    is_retryable,
    security_code,
    www_authenticate,
)
from jdlib.security.interfaces import (
    GatewayAdapter,
    GatewayIdentity,
    OutboundToken,
    RateLimitDecision,
    RateLimiter,
    TokenProvider,
    TokenValidator,
    ValidatedToken,
)
from jdlib.security.responses import ErrorResponse, error_response

__all__ = [
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
    "AuthorizationUnavailable",
    "SecurityClassification",
    "SecurityCode",
    "SecurityConfigurationError",
    "SecurityDescriptor",
    "describe_error",
    "is_retryable",
    "security_code",
    "www_authenticate",
    # responses
    "ErrorResponse",
    "error_response",
    # interfaces
    "GatewayAdapter",
    "GatewayIdentity",
    "OutboundToken",
    "RateLimitDecision",
    "RateLimiter",
    "TokenProvider",
    "TokenValidator",
    "ValidatedToken",
]
