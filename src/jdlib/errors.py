class JdlibError(Exception):
    pass


class MissingTenantContext(JdlibError):
    pass


class TenantNotFound(JdlibError):
    def __init__(self, tenant: str) -> None:
        super().__init__(f"tenant not found: {tenant}")


class TenantAccessDenied(JdlibError):
    pass


class TenantSuspended(JdlibError):
    pass


class TenantNotWritable(JdlibError):
    pass


class CrossTenantReferenceError(JdlibError):
    def __init__(self, reference: str, expected_tenant: str, actual_tenant: str) -> None:
        super().__init__(
            f"cross-tenant reference {reference}: expected {expected_tenant}, got {actual_tenant}"
        )


class UnscopedBulkOperation(JdlibError):
    pass


class InvalidReference(JdlibError):
    pass


class InvalidResourcePermission(JdlibError):
    pass


class UnknownResourceType(JdlibError):
    pass


class UnknownPermission(JdlibError):
    pass


class RoleScopeMismatch(JdlibError):
    pass


class AuthenticationError(JdlibError):
    pass


class InvalidToken(AuthenticationError):
    pass


class ExpiredToken(AuthenticationError):
    pass


class UnknownPrincipal(AuthenticationError):
    pass


class AuthorizationError(JdlibError):
    pass


class PermissionDenied(AuthorizationError):
    pass


class AuthorizationUnavailable(AuthorizationError):
    """A policy decision could not be taken because the engine was unavailable.

    Raised instead of :class:`PermissionDenied` when a decision point reports
    that it could not reach a verdict. It is still a **denial** — nothing is
    ever allowed because an engine was down — but it is reported as ``503`` and
    marked retryable, so a client can tell "you may not" from "we could not
    decide yet" and operators can alert on the difference. Messages never name
    the engine or its endpoint.
    """


class RoleEscalationBlocked(AuthorizationError):
    pass


class StrategyCapabilityError(JdlibError):
    pass


class PoolCapacityError(JdlibError):
    pass


class TenantOperationInProgress(JdlibError):
    pass


class RelocationPhaseError(JdlibError):
    pass


class UnscopedRawSql(JdlibError):
    pass


class SchemaLintError(JdlibError):
    def __init__(self, issues: list[str]) -> None:
        super().__init__("schema lint failed: " + "; ".join(issues))
        self.issues = issues


class ProvisioningError(JdlibError):
    pass


class MigrationError(JdlibError):
    pass


__all__ = [
    "MissingTenantContext",
    "TenantNotFound",
    "TenantAccessDenied",
    "TenantSuspended",
    "TenantNotWritable",
    "CrossTenantReferenceError",
    "UnscopedBulkOperation",
    "InvalidReference",
    "InvalidResourcePermission",
    "UnknownResourceType",
    "UnknownPermission",
    "RoleScopeMismatch",
    "AuthenticationError",
    "InvalidToken",
    "ExpiredToken",
    "UnknownPrincipal",
    "AuthorizationError",
    "PermissionDenied",
    "RoleEscalationBlocked",
    "StrategyCapabilityError",
    "PoolCapacityError",
    "TenantOperationInProgress",
    "RelocationPhaseError",
    "UnscopedRawSql",
    "SchemaLintError",
    "ProvisioningError",
    "MigrationError",
]
