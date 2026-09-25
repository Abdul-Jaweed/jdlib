"""Security audit vocabulary and envelope (directive §4).

The audit trail is a security control, so event *names* are a contract: a log
consumer routes on them and an evidence mapping cites them. They are pinned by
``tests/unit/security/test_audit_events.py`` to the directive's list.

Rules enforced here, not by convention:

* metadata is validated and sanitized at construction — a caller cannot log a
  secret by accident, a non-JSON value cannot reach the sink, and an
  unbounded payload cannot be used to exhaust storage,
* identifiers default from the ambient security context, so a caller inside a
  request does not have to thread request/correlation/trace ids through, while a
  platform event (no request) is equally valid,
* ``repr`` never prints metadata values, so a stray log line or traceback
  cannot disclose them either.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum

from jdlib._uuid import uuid7
from jdlib.security.context import current_security_context_or_none
from jdlib.security.redaction import REDACTED, is_sensitive_key, redact_text

MAX_METADATA_ENTRIES = 32
MAX_VALUE_LENGTH = 1024
MAX_LIST_LENGTH = 256
MAX_INTEGER = 2**63


class SecurityEventType(StrEnum):
    """Stable security event names (directive §4)."""

    # -- authentication
    AUTH_LOGIN_SUCCESS = "AUTH_LOGIN_SUCCESS"
    AUTH_LOGIN_FAILURE = "AUTH_LOGIN_FAILURE"
    AUTH_TOKEN_INVALID = "AUTH_TOKEN_INVALID"
    AUTH_TOKEN_EXPIRED = "AUTH_TOKEN_EXPIRED"
    AUTH_TOKEN_REVOKED = "AUTH_TOKEN_REVOKED"
    AUTH_API_KEY_USED = "AUTH_API_KEY_USED"
    AUTH_SERVICE_AUTHENTICATED = "AUTH_SERVICE_AUTHENTICATED"

    # -- authorization
    AUTHZ_ALLOW = "AUTHZ_ALLOW"
    AUTHZ_DENY = "AUTHZ_DENY"
    AUTHZ_PDP_ERROR = "AUTHZ_PDP_ERROR"
    AUTHZ_POLICY_CHANGED = "AUTHZ_POLICY_CHANGED"
    ROLE_ASSIGNED = "ROLE_ASSIGNED"
    ROLE_REVOKED = "ROLE_REVOKED"
    PERMISSION_CHANGED = "PERMISSION_CHANGED"
    RESOURCE_GRANT_CREATED = "RESOURCE_GRANT_CREATED"
    RESOURCE_GRANT_REVOKED = "RESOURCE_GRANT_REVOKED"

    # -- tenant lifecycle
    TENANT_CREATED = "TENANT_CREATED"
    TENANT_PROVISIONED = "TENANT_PROVISIONED"
    TENANT_SUSPENDED = "TENANT_SUSPENDED"
    TENANT_RESUMED = "TENANT_RESUMED"
    TENANT_ARCHIVED = "TENANT_ARCHIVED"
    TENANT_DEPROVISIONED = "TENANT_DEPROVISIONED"
    TENANT_PURGED = "TENANT_PURGED"
    TENANT_RELOCATED = "TENANT_RELOCATED"

    # -- privileged operations
    PRIVILEGE_ISSUED = "PRIVILEGE_ISSUED"
    PRIVILEGE_USED = "PRIVILEGE_USED"
    PRIVILEGE_EXPIRED = "PRIVILEGE_EXPIRED"

    # -- security-sensitive operations
    RAW_SQL_REJECTED = "RAW_SQL_REJECTED"
    RAW_SQL_PRIVILEGED = "RAW_SQL_PRIVILEGED"
    CROSS_TENANT_ACCESS_REJECTED = "CROSS_TENANT_ACCESS_REJECTED"
    SECURITY_CONFIGURATION_CHANGED = "SECURITY_CONFIGURATION_CHANGED"
    CREDENTIAL_CREATED = "CREDENTIAL_CREATED"
    CREDENTIAL_REVOKED = "CREDENTIAL_REVOKED"
    CREDENTIAL_ROTATED = "CREDENTIAL_ROTATED"

    # -- successor capabilities: resources, connectors, compiled queries
    # Credential rotation reuses CREDENTIAL_ROTATED above; delegation reuses the PRIVILEGE_*
    # vocabulary, because a delegated privilege is a privilege and not a second concept.
    RESOURCE_HYDRATED = "RESOURCE_HYDRATED"
    RESOURCE_HYDRATION_REFUSED = "RESOURCE_HYDRATION_REFUSED"
    CONNECTOR_REGISTERED = "CONNECTOR_REGISTERED"
    CONNECTOR_ACQUIRED = "CONNECTOR_ACQUIRED"
    QUERY_REJECTED = "QUERY_REJECTED"

    # -- audit trail access (directive §6.5: audit access is itself an event)
    AUDIT_READ_DENIED = "AUDIT_READ_DENIED"
    AUDIT_EXPORTED = "AUDIT_EXPORTED"

    # -- MCP surface (directive §27: the events a second entry surface must produce)
    MCP_REQUEST = "MCP_REQUEST"
    MCP_TOOL_INVOKED = "MCP_TOOL_INVOKED"
    MCP_RESOURCE_READ = "MCP_RESOURCE_READ"
    MCP_ERROR = "MCP_ERROR"

    @property
    def category(self) -> str:
        """Domain the event belongs to, so consumers can route without parsing."""
        prefix = self.value.split("_", 1)[0]
        if prefix == "AUTH":
            return "authentication"
        if prefix in {"AUTHZ", "ROLE", "PERMISSION", "RESOURCE"}:
            return "authorization"
        if prefix == "TENANT":
            return "tenancy"
        if prefix == "PRIVILEGE":
            return "privilege"
        if prefix == "AUDIT":
            return "audit"
        if prefix == "MCP":
            return "mcp"
        if prefix == "CONNECTOR":
            return "connector"
        return "security"


class AuditOutcome(StrEnum):
    """What happened."""

    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"
    DENIED = "DENIED"
    ERROR = "ERROR"


class AuditSource(StrEnum):
    """Where the event was produced."""

    API = "API"
    GATEWAY = "GATEWAY"
    SERVICE = "SERVICE"
    SYSTEM = "SYSTEM"
    BACKGROUND_JOB = "BACKGROUND_JOB"
    CLI = "CLI"


_KEY_PATTERN = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")


def _safe_value(key: str, value: object) -> object:
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        if abs(value) >= MAX_INTEGER:
            raise ValueError(f"metadata value for {key!r} is out of range")
        return value
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise ValueError(f"metadata value for {key!r} is not finite")
        return value
    if isinstance(value, str):
        if len(value) > MAX_VALUE_LENGTH:
            raise ValueError(f"metadata value for {key!r} is too long")
        return REDACTED if is_sensitive_key(key) else redact_text(value)
    if isinstance(value, Sequence):
        if len(value) > MAX_LIST_LENGTH:
            raise ValueError(f"metadata list for {key!r} is too long")
        return [_safe_scalar(key, item) for item in value]
    raise ValueError(f"metadata value for {key!r} is not auditable: {type(value).__name__}")


def _safe_scalar(key: str, value: object) -> object:
    if isinstance(value, str) and len(value) > MAX_VALUE_LENGTH:
        raise ValueError(f"metadata value for {key!r} is too long")
    if isinstance(value, (Mapping, Sequence)) and not isinstance(value, str):
        raise ValueError(f"metadata for {key!r} is nested too deeply")
    if isinstance(value, int) and not isinstance(value, bool) and abs(value) >= MAX_INTEGER:
        raise ValueError(f"metadata value for {key!r} is out of range")
    if isinstance(value, float) and (value != value or value in (float("inf"), float("-inf"))):
        raise ValueError(f"metadata value for {key!r} is not finite")
    if isinstance(value, str):
        return REDACTED if is_sensitive_key(key) else redact_text(value)
    return value


def audit_metadata(mapping: Mapping[str, object] | None) -> dict[str, object]:
    """Validate, sanitize and copy audit metadata.

    Raises :class:`TypeError` for a non-mapping and :class:`ValueError` for a
    payload that cannot be safely audited (non-JSON values, nesting, oversized
    strings, out-of-range integers) — failing loudly at the call site rather than
    silently dropping evidence or storing something unqueryable.
    """
    if mapping is None:
        return {}
    if not isinstance(mapping, Mapping):
        raise TypeError("audit metadata must be a mapping")
    if len(mapping) > MAX_METADATA_ENTRIES:
        raise ValueError("audit metadata has too many entries")
    cleaned: dict[str, object] = {}
    for key, value in mapping.items():
        if not isinstance(key, str):
            raise TypeError("audit metadata keys must be strings")
        if not _KEY_PATTERN.match(key):
            raise ValueError(f"audit metadata key {key!r} is not a stable identifier")
        cleaned[key] = _safe_value(key, value)
    return cleaned


@dataclass(frozen=True, slots=True)
class SecurityAuditEvent:
    """One security-relevant event, ready to be persisted or exported."""

    event_type: SecurityEventType
    outcome: AuditOutcome
    action: str
    source: AuditSource
    event_id: uuid.UUID = field(default_factory=uuid7)
    occurred_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    tenant_id: uuid.UUID | None = None
    principal_id: uuid.UUID | None = None
    principal_kind: str | None = None
    resource_type: str | None = None
    resource_id: str | None = None
    request_id: str | None = None
    correlation_id: str | None = None
    trace_id: str | None = None
    metadata: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "metadata", audit_metadata(self.metadata))
        if not isinstance(self.event_type, SecurityEventType):
            object.__setattr__(self, "event_type", SecurityEventType(str(self.event_type)))
        if not isinstance(self.outcome, AuditOutcome):
            object.__setattr__(self, "outcome", AuditOutcome(str(self.outcome)))
        if not isinstance(self.source, AuditSource):
            object.__setattr__(self, "source", AuditSource(str(self.source)))
        context = current_security_context_or_none()
        if context is None:
            return
        tenant = self.tenant_id or (context.tenant.tenant_id if context.tenant else None)
        if tenant is None:
            tenant = context.principal.tenant_id
        object.__setattr__(self, "tenant_id", tenant)
        object.__setattr__(self, "principal_id", self.principal_id or context.principal.id)
        object.__setattr__(
            self, "principal_kind", self.principal_kind or context.principal.kind.value
        )
        object.__setattr__(self, "request_id", self.request_id or context.request_ids.request_id)
        object.__setattr__(
            self, "correlation_id", self.correlation_id or context.request_ids.correlation_id
        )
        object.__setattr__(self, "trace_id", self.trace_id or context.request_ids.trace_id)

    def __repr__(self) -> str:
        return (
            f"SecurityAuditEvent(event_type={self.event_type.value!r}, "
            f"outcome={self.outcome.value!r}, action={self.action!r}, "
            f"tenant_id={self.tenant_id!r}, principal_id={self.principal_id!r}, "
            f"metadata_keys={sorted(self.metadata)!r})"
        )

    def as_dict(self) -> dict[str, object]:
        """JSON-serializable representation."""
        return {
            "event_id": str(self.event_id),
            "event_type": self.event_type.value,
            "category": self.event_type.category,
            "outcome": self.outcome.value,
            "action": self.action,
            "source": self.source.value,
            "occurred_at": self.occurred_at.isoformat(),
            "tenant_id": str(self.tenant_id) if self.tenant_id else None,
            "principal_id": str(self.principal_id) if self.principal_id else None,
            "principal_kind": self.principal_kind,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "request_id": self.request_id,
            "correlation_id": self.correlation_id,
            "trace_id": self.trace_id,
            "metadata": dict(self.metadata),
        }

    def as_row(self) -> dict[str, object]:
        """Column mapping for the tenant-scoped audit table."""
        return {
            "id": self.event_id,
            "actor_type": _actor_type(self.principal_kind),
            "actor_id": self.principal_id,
            "action": self.action,
            "target_type": self.resource_type,
            "target_id": _as_uuid(self.resource_id),
            "event_type": self.event_type.value,
            "outcome": self.outcome.value,
            "source": self.source.value,
            "metadata": dict(self.metadata),
            "request_id": self.request_id,
            "correlation_id": self.correlation_id,
            "trace_id": self.trace_id,
            "occurred_at": self.occurred_at,
        }


_ACTOR_TYPES = frozenset({"user", "service_account", "platform_operator", "system"})


def _actor_type(principal_kind: str | None) -> str:
    """Map a principal kind onto the audit table's constraint.

    The table accepts ``user``/``service_account``/``platform_operator``/
    ``system``; a kind outside that set (``anonymous``, or a caller that raised
    an event outside any request) is recorded as ``system`` so the information
    is never silently dropped *and* an audit write never fails a database
    constraint — a failing audit write would be the worse outcome.
    """
    return principal_kind if principal_kind in _ACTOR_TYPES else "system"


def _as_uuid(value: str | None) -> uuid.UUID | None:
    if value is None:
        return None
    try:
        return uuid.UUID(value)
    except ValueError:
        return None


__all__ = [
    "AuditOutcome",
    "AuditSource",
    "SecurityAuditEvent",
    "SecurityEventType",
    "audit_metadata",
]
