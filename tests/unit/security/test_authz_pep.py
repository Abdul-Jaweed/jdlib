"""Phase 3: the enforcement point (directive §15, §16).

Application code calls the PEP, never a policy engine. What is under test:

* a denied decision raises a 403 with a safe message (no attribute values, no
  internal policy internals beyond the id/version),
* a request with no authenticated principal raises 401 and a non-tenant-bound
  context fails closed rather than being treated as a wildcard,
* asking about another tenant's resource raises 404 without consulting the
  engine at all,
* an engine that is unavailable, timed out or malformed still yields a denial —
  never a bypass — which is the critical fail-closed property of directive §16,
* decisions are observable (the audit seam) for allow, deny and degraded alike,
  and an observer failure can never turn a denial into an allow.
"""

from __future__ import annotations

import contextlib
import uuid
from datetime import UTC, datetime

import pytest

from jdlib.context import Principal, PrincipalKind, TenantContext
from jdlib.control.enums import PlacementStrategy
from jdlib.errors import (
    AuthenticationError,
    AuthorizationError,
    AuthorizationUnavailable,
    MissingTenantContext,
    PermissionDenied,
    TenantAccessDenied,
)
from jdlib.security.authz.decision import AuthorizationDecision, AuthorizationQuery
from jdlib.security.authz.interfaces import PolicyDecisionPoint
from jdlib.security.authz.pep import AuthorizationPEP
from jdlib.security.context import AuthMethod, RequestIds, SecurityContext, TokenMetadata
from jdlib.security.errors import describe_error

TENANT_ID = uuid.UUID("11111111-2222-3333-4444-555555555555")
OTHER_TENANT_ID = uuid.UUID("99999999-8888-7777-6666-555555555555")
NOW = datetime(2026, 6, 1, 12, 0, tzinfo=UTC)
SECRET_ATTRIBUTE = "confidential-classification-value"


class StubPDP:
    def __init__(self, decision: AuthorizationDecision) -> None:
        self.decision = decision
        self.queries: list[AuthorizationQuery] = []

    async def decide(self, query: AuthorizationQuery) -> AuthorizationDecision:
        self.queries.append(query)
        return self.decision


class ExplodingPDP:
    async def decide(self, query: AuthorizationQuery) -> AuthorizationDecision:
        raise AssertionError("the engine must not be consulted for this request")


def _query(tenant_id: uuid.UUID = TENANT_ID) -> AuthorizationQuery:
    return AuthorizationQuery(
        principal_id="user-1",
        tenant_id=tenant_id,
        resource_kind="document",
        resource_id="doc-42",
        actions=("read",),
        attributes={"classification": SECRET_ATTRIBUTE},
    )


def _tenant_context(tenant_id: uuid.UUID = TENANT_ID) -> TenantContext:
    principal = Principal(kind=PrincipalKind.USER, id=uuid.uuid4(), tenant_id=tenant_id)
    return TenantContext(
        tenant_id=tenant_id,
        tenant_slug="acme",
        strategy=PlacementStrategy.SHARED,
        principal=principal,
        request_id="req-1",
        correlation_id="corr-1",
    )


def _context(tenant_id: uuid.UUID = TENANT_ID) -> SecurityContext:
    return SecurityContext.from_tenant_context(
        tenant=_tenant_context(tenant_id),
        auth_method=AuthMethod.JWT,
        token_metadata=TokenMetadata(issuer="https://idp.test", subject="user-1"),
    )


def _allowed() -> AuthorizationDecision:
    return AuthorizationDecision.allow(
        decided_at=NOW, policy_id="document", policy_version="default"
    )


def _denied() -> AuthorizationDecision:
    return AuthorizationDecision.deny(
        reason="no_allow",
        decided_at=NOW,
        policy_id="document",
        policy_version="default",
        denied_actions=("read",),
    )


def _degraded() -> AuthorizationDecision:
    return AuthorizationDecision.unavailable(reason="engine_unavailable", decided_at=NOW)


def test_pep_satisfies_the_port_shape() -> None:
    pep = AuthorizationPEP(pdp=StubPDP(_allowed()))
    assert isinstance(pep, AuthorizationPEP)
    assert isinstance(StubPDP(_allowed()), PolicyDecisionPoint)


async def test_allow_returns_the_decision() -> None:
    pdp = StubPDP(_allowed())
    decision = await AuthorizationPEP(pdp=pdp).require(_query())
    assert decision.allowed is True
    assert len(pdp.queries) == 1


async def test_deny_raises_403_with_a_safe_message() -> None:
    pep = AuthorizationPEP(pdp=StubPDP(_denied()))
    with pytest.raises(PermissionDenied) as excinfo:
        await pep.require(_query())
    message = str(excinfo.value)
    assert "doc-42" in message
    assert "no_allow" in message
    assert SECRET_ATTRIBUTE not in message
    assert describe_error(PermissionDenied).http_status == 403


async def test_degraded_engine_still_denies() -> None:
    # The critical directive §16 property, enforced at the enforcement point.
    pep = AuthorizationPEP(pdp=StubPDP(_degraded()))
    with pytest.raises(AuthorizationUnavailable) as excinfo:
        await pep.require(_query())
    assert "engine_unavailable" in str(excinfo.value)
    # Denied either way; reported as 503 so an outage is not read as "you may not".
    assert describe_error(AuthorizationUnavailable).http_status == 503
    assert describe_error(AuthorizationUnavailable).retryable is True
    assert isinstance(excinfo.value, AuthorizationError)


async def test_anonymous_context_raises_401() -> None:
    pep = AuthorizationPEP(pdp=ExplodingPDP())
    with pytest.raises(AuthenticationError):
        await pep.require(_query(), context=SecurityContext.anonymous())


async def test_context_without_a_tenant_fails_closed() -> None:
    context = SecurityContext(
        principal=Principal(kind=PrincipalKind.USER, id=uuid.uuid4(), tenant_id=None),
        request_ids=RequestIds(request_id="req-1", correlation_id="corr-1", trace_id=None),
        auth_method=AuthMethod.JWT,
        tenant=None,
    )
    pep = AuthorizationPEP(pdp=ExplodingPDP())
    with pytest.raises(MissingTenantContext):
        await pep.require(_query(), context=context)


async def test_cross_tenant_query_is_refused_before_asking_the_engine() -> None:
    pep = AuthorizationPEP(pdp=ExplodingPDP())
    with pytest.raises(TenantAccessDenied):
        await pep.require(_query(tenant_id=OTHER_TENANT_ID), context=_context())


async def test_check_does_not_raise_for_denials() -> None:
    pep = AuthorizationPEP(pdp=StubPDP(_denied()))
    decision = await pep.check(_query())
    assert decision.allowed is False
    assert decision.reason == "no_allow"


async def test_check_does_not_raise_for_a_degraded_engine() -> None:
    pep = AuthorizationPEP(pdp=StubPDP(_degraded()))
    decision = await pep.check(_query())
    assert decision.allowed is False
    assert decision.degraded is True


async def test_decisions_are_observable_for_audit() -> None:
    seen: list[tuple[bool, str]] = []

    async def observe(query: AuthorizationQuery, decision: AuthorizationDecision) -> None:
        seen.append((decision.allowed, decision.safe_metadata()["decision"]))

    for decision in (_allowed(), _denied(), _degraded()):
        pep = AuthorizationPEP(pdp=StubPDP(decision), on_decision=observe)
        with contextlib.suppress(PermissionDenied, AuthorizationUnavailable):
            await pep.require(_query())
    assert seen == [(True, "ALLOW"), (False, "DENY"), (False, "DENY")]


async def test_an_observer_failure_cannot_turn_a_denial_into_an_allow() -> None:
    async def observe(query: AuthorizationQuery, decision: AuthorizationDecision) -> None:
        raise RuntimeError("audit sink down")

    pep = AuthorizationPEP(pdp=StubPDP(_denied()), on_decision=observe)
    with pytest.raises(RuntimeError):
        await pep.require(_query())


async def test_an_observer_failure_fails_closed_even_for_an_allow() -> None:
    async def observe(query: AuthorizationQuery, decision: AuthorizationDecision) -> None:
        raise RuntimeError("audit sink down")

    pep = AuthorizationPEP(pdp=StubPDP(_allowed()), on_decision=observe)
    with pytest.raises(RuntimeError):
        await pep.require(_query())
