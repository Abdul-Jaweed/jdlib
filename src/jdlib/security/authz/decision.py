"""Vendor-neutral authorization inputs and decisions (directive §15, §17).

Nothing in this module imports Cerbos, HTTP transports or a web framework, so
application code can depend on it without knowing which policy engine answers.

Two invariants make the model hard to bend into a fail-open bug:

* an allowed decision must carry an explicit ALLOW effect,
* a decision produced without a policy engine (unavailable, timeout, malformed
  response) is degraded and can never be allowed.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from types import MappingProxyType


class Effect(StrEnum):
    """The outcome a policy engine can return."""

    ALLOW = "ALLOW"
    DENY = "DENY"


def _frozen(mapping: Mapping[str, object] | None) -> Mapping[str, object]:
    """Copy into an immutable mapping (callers cannot mutate it afterwards)."""
    return MappingProxyType(dict(mapping or {}))


@dataclass(frozen=True, slots=True)
class AuthorizationQuery:
    """What is being asked of the policy engine, in neutral terms.

    ``actions`` is never empty: an authorization question without an action is a
    programming error, not a request to be denied silently.
    """

    principal_id: str
    tenant_id: uuid.UUID
    resource_kind: str
    resource_id: str
    actions: tuple[str, ...]
    roles: frozenset[str] = frozenset()
    attributes: Mapping[str, object] = field(default_factory=dict)
    principal_attributes: Mapping[str, object] = field(default_factory=dict)
    request_id: str | None = None

    def __post_init__(self) -> None:
        if not self.principal_id:
            raise ValueError("an authorization query needs a principal")
        if self.tenant_id is None:
            raise ValueError("an authorization query needs a tenant binding")
        if not self.resource_kind:
            raise ValueError("an authorization query needs a resource kind")
        if not self.resource_id:
            raise ValueError("an authorization query needs a resource id")
        actions = tuple(self.actions)
        if not actions:
            raise ValueError("an authorization query needs at least one action")
        object.__setattr__(self, "actions", actions)
        object.__setattr__(self, "roles", frozenset(self.roles))
        object.__setattr__(self, "attributes", _frozen(self.attributes))
        object.__setattr__(self, "principal_attributes", _frozen(self.principal_attributes))

    def __repr__(self) -> str:
        """Represent the query without any attribute values.

        Attribute values are resource data; keeping them out of ``repr`` keeps
        them out of logs, tracebacks and error reports by default.
        """
        return (
            f"AuthorizationQuery(principal_id={self.principal_id!r}, "
            f"tenant_id={self.tenant_id!s}, resource={self.resource_kind}:{self.resource_id}, "
            f"actions={list(self.actions)}, roles={sorted(self.roles)}, "
            f"attributes={sorted(self.attributes)}, "
            f"principal_attributes={sorted(self.principal_attributes)})"
        )


@dataclass(frozen=True, slots=True)
class AuthorizationDecision:
    """The answer, with safe metadata (directive §17).

    ``safe_metadata()`` is what may be handed to clients, logs or audit: the
    decision, the policy id and version that produced it, the timestamp and a
    machine-readable reason. Raw attributes and unmatched internal policy
    details never leave through it.
    """

    allowed: bool
    effect: Effect
    decided_at: datetime
    policy_id: str | None = None
    policy_version: str | None = None
    reason: str = "no_allow"
    degraded: bool = False
    denied_actions: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.allowed and self.effect is not Effect.ALLOW:
            raise ValueError("an allowed decision must carry an ALLOW effect")
        if self.allowed and self.degraded:
            raise ValueError("a degraded decision can never be allowed")
        object.__setattr__(self, "denied_actions", tuple(self.denied_actions))

    # -- constructors ------------------------------------------------------

    @classmethod
    def allow(
        cls,
        *,
        decided_at: datetime,
        policy_id: str | None = None,
        policy_version: str | None = None,
    ) -> AuthorizationDecision:
        return cls(
            allowed=True,
            effect=Effect.ALLOW,
            decided_at=decided_at,
            policy_id=policy_id,
            policy_version=policy_version,
            reason="allowed",
        )

    @classmethod
    def deny(
        cls,
        *,
        reason: str,
        decided_at: datetime,
        policy_id: str | None = None,
        policy_version: str | None = None,
        denied_actions: tuple[str, ...] = (),
    ) -> AuthorizationDecision:
        return cls(
            allowed=False,
            effect=Effect.DENY,
            decided_at=decided_at,
            policy_id=policy_id,
            policy_version=policy_version,
            reason=reason,
            denied_actions=denied_actions,
        )

    @classmethod
    def unavailable(cls, *, reason: str, decided_at: datetime) -> AuthorizationDecision:
        """Fail closed: no policy engine answered, so nothing is allowed."""
        return cls(
            allowed=False,
            effect=Effect.DENY,
            decided_at=decided_at,
            reason=reason,
            degraded=True,
        )

    # -- safe output -------------------------------------------------------

    def safe_metadata(self) -> dict[str, str]:
        """The subset of this decision that may leave the trust boundary."""
        return {
            "decision": self.effect.value,
            "policy_id": self.policy_id or "",
            "policy_version": self.policy_version or "",
            "decided_at": self.decided_at.isoformat(),
            "reason": self.reason,
        }

    def __repr__(self) -> str:
        return (
            f"AuthorizationDecision(effect={self.effect.value}, degraded={self.degraded}, "
            f"policy_id={self.policy_id!r}, policy_version={self.policy_version!r}, "
            f"denied_actions={list(self.denied_actions)})"
        )


__all__ = ["AuthorizationDecision", "AuthorizationQuery", "Effect"]
