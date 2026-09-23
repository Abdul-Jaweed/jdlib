"""Stable machine-readable security error model (spec #21, #75).

The model is declarative: every :class:`~jdlib.errors.JdlibError` exported by
the library carries a :class:`SecurityDescriptor` describing

* a stable ``code`` that API clients can branch on,
* the HTTP status the runtime mapping produces,
* whether the failure is transient (safe to retry with backoff),
* the security classification used for audit and metrics.

Descriptors describe behaviour that already exists; they do not change it.
``tests/unit/security/test_security_errors.py`` asserts that every declared
descriptor agrees with the runtime ``http_status_for`` mapping, so the model
cannot silently drift from enforcement.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from jdlib import errors


class SecurityCode(StrEnum):
    """Stable, machine-readable security error codes."""

    # -- Authentication
    AUTHENTICATION_REQUIRED = "AUTHENTICATION_REQUIRED"
    INVALID_TOKEN = "INVALID_TOKEN"
    EXPIRED_TOKEN = "EXPIRED_TOKEN"
    INVALID_AUDIENCE = "INVALID_AUDIENCE"
    INVALID_ISSUER = "INVALID_ISSUER"
    INSUFFICIENT_SCOPE = "INSUFFICIENT_SCOPE"
    UNKNOWN_PRINCIPAL = "UNKNOWN_PRINCIPAL"

    # -- Authorization and policy decisions
    PERMISSION_DENIED = "PERMISSION_DENIED"
    ROLE_ESCALATION_BLOCKED = "ROLE_ESCALATION_BLOCKED"
    POLICY_DENIED = "POLICY_DENIED"
    POLICY_UNAVAILABLE = "POLICY_UNAVAILABLE"

    # -- Tenancy
    MISSING_TENANT_CONTEXT = "MISSING_TENANT_CONTEXT"
    TENANT_NOT_FOUND = "TENANT_NOT_FOUND"
    TENANT_ACCESS_DENIED = "TENANT_ACCESS_DENIED"
    TENANT_SUSPENDED = "TENANT_SUSPENDED"
    TENANT_NOT_SERVABLE = "TENANT_NOT_SERVABLE"
    TENANT_OPERATION_IN_PROGRESS = "TENANT_OPERATION_IN_PROGRESS"
    RELOCATION_IN_PROGRESS = "RELOCATION_IN_PROGRESS"

    # -- Data boundary
    CROSS_TENANT_ACCESS = "CROSS_TENANT_ACCESS"
    UNSCOPED_DATA_OPERATION = "UNSCOPED_DATA_OPERATION"
    INVALID_REFERENCE = "INVALID_REFERENCE"

    # -- Configuration and schema
    SECURITY_CONFIGURATION_ERROR = "SECURITY_CONFIGURATION_ERROR"
    SCHEMA_LINT_FAILED = "SCHEMA_LINT_FAILED"

    # -- Availability and internal faults
    CAPACITY_EXCEEDED = "CAPACITY_EXCEEDED"
    PROVISIONING_ERROR = "PROVISIONING_ERROR"
    MIGRATION_ERROR = "MIGRATION_ERROR"
    INTERNAL_ERROR = "INTERNAL_ERROR"


class SecurityClassification(StrEnum):
    """Security domain a failure belongs to (for audit, metrics, policy)."""

    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    TENANCY = "tenancy"
    DATA_BOUNDARY = "data_boundary"
    CONFIGURATION = "configuration"
    AVAILABILITY = "availability"
    INTERNAL = "internal"


@dataclass(frozen=True, slots=True)
class SecurityDescriptor:
    """Immutable description of how a failure is reported."""

    code: SecurityCode
    http_status: int
    retryable: bool
    classification: SecurityClassification


_DESCRIPTOR_DEFAULT = SecurityDescriptor(
    code=SecurityCode.INTERNAL_ERROR,
    http_status=500,
    retryable=False,
    classification=SecurityClassification.INTERNAL,
)


class SecurityConfigurationError(errors.JdlibError):
    """Unsafe or incoherent security configuration (spec #21, #31, #75).

    Raised while building or validating security configuration so that
    insecure combinations fail startup instead of failing open at runtime.
    Messages describe the offending setting and never contain secret values.
    """


_DESCRIPTORS: dict[type[BaseException], SecurityDescriptor] = {
    # Authentication
    errors.AuthenticationError: SecurityDescriptor(
        SecurityCode.AUTHENTICATION_REQUIRED, 401, False, SecurityClassification.AUTHENTICATION
    ),
    errors.InvalidToken: SecurityDescriptor(
        SecurityCode.INVALID_TOKEN, 401, False, SecurityClassification.AUTHENTICATION
    ),
    errors.ExpiredToken: SecurityDescriptor(
        SecurityCode.EXPIRED_TOKEN, 401, False, SecurityClassification.AUTHENTICATION
    ),
    errors.UnknownPrincipal: SecurityDescriptor(
        SecurityCode.UNKNOWN_PRINCIPAL, 401, False, SecurityClassification.AUTHENTICATION
    ),
    # Authorization
    errors.AuthorizationError: SecurityDescriptor(
        SecurityCode.PERMISSION_DENIED, 403, False, SecurityClassification.AUTHORIZATION
    ),
    errors.PermissionDenied: SecurityDescriptor(
        SecurityCode.PERMISSION_DENIED, 403, False, SecurityClassification.AUTHORIZATION
    ),
    errors.RoleEscalationBlocked: SecurityDescriptor(
        SecurityCode.ROLE_ESCALATION_BLOCKED, 403, False, SecurityClassification.AUTHORIZATION
    ),
    # Tenancy
    errors.MissingTenantContext: SecurityDescriptor(
        SecurityCode.MISSING_TENANT_CONTEXT, 500, False, SecurityClassification.TENANCY
    ),
    errors.TenantNotFound: SecurityDescriptor(
        SecurityCode.TENANT_NOT_FOUND, 404, False, SecurityClassification.TENANCY
    ),
    errors.TenantAccessDenied: SecurityDescriptor(
        SecurityCode.TENANT_ACCESS_DENIED, 404, False, SecurityClassification.TENANCY
    ),
    errors.TenantSuspended: SecurityDescriptor(
        SecurityCode.TENANT_SUSPENDED, 423, False, SecurityClassification.TENANCY
    ),
    errors.TenantNotWritable: SecurityDescriptor(
        SecurityCode.TENANT_NOT_SERVABLE, 423, False, SecurityClassification.TENANCY
    ),
    errors.TenantOperationInProgress: SecurityDescriptor(
        SecurityCode.TENANT_OPERATION_IN_PROGRESS, 500, True, SecurityClassification.TENANCY
    ),
    errors.RelocationPhaseError: SecurityDescriptor(
        SecurityCode.RELOCATION_IN_PROGRESS, 500, True, SecurityClassification.TENANCY
    ),
    # Data boundary
    errors.CrossTenantReferenceError: SecurityDescriptor(
        SecurityCode.CROSS_TENANT_ACCESS, 409, False, SecurityClassification.DATA_BOUNDARY
    ),
    errors.UnscopedBulkOperation: SecurityDescriptor(
        SecurityCode.UNSCOPED_DATA_OPERATION, 500, False, SecurityClassification.DATA_BOUNDARY
    ),
    errors.UnscopedRawSql: SecurityDescriptor(
        SecurityCode.UNSCOPED_DATA_OPERATION, 500, False, SecurityClassification.DATA_BOUNDARY
    ),
    errors.InvalidReference: SecurityDescriptor(
        SecurityCode.INVALID_REFERENCE, 409, False, SecurityClassification.DATA_BOUNDARY
    ),
    # Configuration and schema
    errors.InvalidResourcePermission: SecurityDescriptor(
        SecurityCode.SECURITY_CONFIGURATION_ERROR,
        500,
        False,
        SecurityClassification.CONFIGURATION,
    ),
    errors.UnknownResourceType: SecurityDescriptor(
        SecurityCode.SECURITY_CONFIGURATION_ERROR,
        500,
        False,
        SecurityClassification.CONFIGURATION,
    ),
    errors.UnknownPermission: SecurityDescriptor(
        SecurityCode.SECURITY_CONFIGURATION_ERROR,
        500,
        False,
        SecurityClassification.CONFIGURATION,
    ),
    errors.RoleScopeMismatch: SecurityDescriptor(
        SecurityCode.SECURITY_CONFIGURATION_ERROR,
        500,
        False,
        SecurityClassification.CONFIGURATION,
    ),
    errors.SchemaLintError: SecurityDescriptor(
        SecurityCode.SCHEMA_LINT_FAILED, 500, False, SecurityClassification.CONFIGURATION
    ),
    SecurityConfigurationError: SecurityDescriptor(
        SecurityCode.SECURITY_CONFIGURATION_ERROR,
        500,
        False,
        SecurityClassification.CONFIGURATION,
    ),
    # Availability and internal faults
    errors.PoolCapacityError: SecurityDescriptor(
        SecurityCode.CAPACITY_EXCEEDED, 500, True, SecurityClassification.AVAILABILITY
    ),
    errors.StrategyCapabilityError: SecurityDescriptor(
        SecurityCode.INTERNAL_ERROR, 500, False, SecurityClassification.INTERNAL
    ),
    errors.ProvisioningError: SecurityDescriptor(
        SecurityCode.PROVISIONING_ERROR, 500, False, SecurityClassification.INTERNAL
    ),
    errors.MigrationError: SecurityDescriptor(
        SecurityCode.MIGRATION_ERROR, 500, False, SecurityClassification.INTERNAL
    ),
}

# RFC 6750 challenge parameters for 401 responses, keyed by stable code.
_CHALLENGES: dict[SecurityCode, str] = {
    SecurityCode.AUTHENTICATION_REQUIRED: 'Bearer realm="jdlib"',
    SecurityCode.INVALID_TOKEN: 'Bearer realm="jdlib", error="invalid_token"',
    SecurityCode.UNKNOWN_PRINCIPAL: 'Bearer realm="jdlib", error="invalid_token"',
    SecurityCode.EXPIRED_TOKEN: (
        'Bearer realm="jdlib", error="invalid_token", '
        'error_description="The access token expired"'
    ),
}


def describe_error(target: BaseException | type[BaseException]) -> SecurityDescriptor:
    """Return the descriptor for an error class or instance.

    Lookup walks the MRO so a consumer subclass inherits the nearest declared
    descriptor. Unknown failures fall back to ``INTERNAL_ERROR`` — fail closed,
    never ``ALLOW``, never a silent success.
    """
    mro: tuple[type[BaseException], ...] = (
        target.__mro__ if isinstance(target, type) else type(target).__mro__
    )
    for klass in mro:
        descriptor = _DESCRIPTORS.get(klass)
        if descriptor is not None:
            return descriptor
    return _DESCRIPTOR_DEFAULT


def security_code(target: BaseException | type[BaseException]) -> SecurityCode:
    """Return the stable code for an error class or instance."""
    return describe_error(target).code


def is_retryable(target: BaseException | type[BaseException]) -> bool:
    """Return whether the failure is transient and safe to retry."""
    return describe_error(target).retryable


def www_authenticate(target: BaseException | type[BaseException]) -> str | None:
    """Return the ``WWW-Authenticate`` challenge for 401 failures."""
    descriptor = describe_error(target)
    if descriptor.http_status != 401:
        return None
    return _CHALLENGES[descriptor.code]


__all__ = [
    "SecurityClassification",
    "SecurityCode",
    "SecurityDescriptor",
    "describe_error",
    "is_retryable",
    "security_code",
    "www_authenticate",
]
