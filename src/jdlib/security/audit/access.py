"""Who may do what with the audit trail (directive §6.1).

Writing the trail and reading it are **different rights**, and reading it is
tenant-bound. Emitting audit events is something every authenticated component
does; reading history is a privileged operation that must be granted explicitly.

The capability model uses the scopes the security context already carries —
there is no second authorization system here. When a principal carries no scopes
at all the failure is an *authentication* failure (401) rather than an
authorization one (403): "authenticate first" and "you authenticated and still
may not" are different answers, and callers act on them differently.

Capability → meaning:

===========================  ==================================================
``audit.write``              emit an application-level audit event
``audit.read``               umbrella: read the current tenant's trail
``audit.read.tenant``        read the current tenant's trail (explicit form)
``audit.read.platform``      read across tenants
``audit.export``             export the trail (requires read authority too)
``audit.verify``             run integrity verification over the trail
===========================  ==================================================
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from jdlib.errors import AuthenticationError, PermissionDenied

_READ_SCOPES = frozenset({"audit.read", "audit.read.tenant"})


class AuditCapability(StrEnum):
    """Capabilities over the audit trail."""

    WRITE = "audit.write"
    READ = "audit.read"
    READ_TENANT = "audit.read.tenant"
    READ_PLATFORM = "audit.read.platform"
    EXPORT = "audit.export"
    VERIFY = "audit.verify"


@dataclass(frozen=True, slots=True)
class AuditAccess:
    """What a principal may do with the audit trail.

    ``scopes=None`` means the principal carries no scopes at all (an
    unauthenticated or non-scope-bearing principal): every capability is denied
    and :meth:`require` reports it as an authentication failure. A platform
    operator reaches the read/verify capabilities without a scope grant, but not
    ``audit.write`` — writing the trail is an application capability, not a
    privileged one.
    """

    scopes: frozenset[str] | None = None
    platform_operator: bool = False
    _granted: frozenset[str] = field(default=frozenset(), repr=False, init=False)

    def allows(self, capability: AuditCapability) -> bool:
        scopes = self.scopes or frozenset()
        if capability is AuditCapability.WRITE:
            return "audit.write" in scopes
        if capability in (AuditCapability.READ, AuditCapability.READ_TENANT):
            return bool(scopes & _READ_SCOPES) or self.platform_operator
        if capability is AuditCapability.READ_PLATFORM:
            return "audit.read.platform" in scopes or self.platform_operator
        if capability is AuditCapability.EXPORT:
            return "audit.export" in scopes or self.platform_operator
        if capability is AuditCapability.VERIFY:
            return "audit.verify" in scopes or self.platform_operator
        return False  # pragma: no cover - unreachable for the current vocabulary

    def require(self, capability: AuditCapability) -> None:
        """Raise unless the capability is granted (401 unauthenticated, 403 otherwise)."""
        if self.allows(capability):
            return
        if not self.scopes and not self.platform_operator:
            raise AuthenticationError("audit access requires an authenticated principal")
        raise PermissionDenied(f"audit capability {capability.value} is not granted")

    @classmethod
    def for_principal(
        cls, scopes: frozenset[str] | None, *, platform_operator: bool = False
    ) -> AuditAccess:
        """Build from the scopes and kind a :class:`~jdlib.context.Principal` carries."""
        return cls(scopes=scopes, platform_operator=platform_operator)


__all__ = ["AuditAccess", "AuditCapability"]
