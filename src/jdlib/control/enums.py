from __future__ import annotations

from enum import StrEnum


class TenantStatus(StrEnum):
    PROVISIONING = "provisioning"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    ARCHIVED = "archived"
    DEPROVISIONING = "deprovisioning"
    DELETED = "deleted"


class PlacementStrategy(StrEnum):
    SHARED = "shared"
    SCHEMA = "schema"
    DATABASE = "database"


class MigrationStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    BLOCKED = "blocked"


class RelocationPhase(StrEnum):
    PENDING = "pending"
    PROVISIONING = "provisioning"
    COPYING = "copying"
    VERIFYING = "verifying"
    FLIPPING = "flipping"
    POST_FLIP_VERIFICATION = "post_flip_verification"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


class OperatorLevel(StrEnum):
    SUPPORT = "support"
    OPERATOR = "operator"
    ADMIN = "admin"


class PrincipalType(StrEnum):
    USER = "user"
    SERVICE_ACCOUNT = "service_account"


class ScopeType(StrEnum):
    TENANT = "tenant"
    ORG = "org"
    TEAM = "team"


class MembershipStatus(StrEnum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    DELETED = "deleted"


class InvitationStatus(StrEnum):
    PENDING = "pending"
    ACCEPTED = "accepted"
    EXPIRED = "expired"
    REVOKED = "revoked"


class ApiKeyStatus(StrEnum):
    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"


class ActorType(StrEnum):
    USER = "user"
    SERVICE_ACCOUNT = "service_account"
    PLATFORM_OPERATOR = "platform_operator"
    SYSTEM = "system"


class AuditSeverity(StrEnum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


def sql_in(column: str, values: type[StrEnum]) -> str:
    rendered = ", ".join(f"'{member.value}'" for member in values)
    return f"{column} IN ({rendered})"
