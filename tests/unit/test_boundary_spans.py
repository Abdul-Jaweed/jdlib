"""Boundary instrumentation (successor Phase 11).

Boundary instrumentation only. The existing span machinery is reused unchanged: `security_span`
is inert without a tracer, validates attributes against the bounded allow-list before they reach
a tracer, refuses identifiers and credentials outright, and never lets a telemetry error reach
the caller. What this phase does is give that seam its missing call sites at the four new
boundaries - and nothing else.

The rejected pattern is the per-method decorator, so the assertions that matter here are the
negative ones: one span per operation, named at the entry point, and no spans at all from the
helpers underneath it.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import pytest

from jdlib.caching.keys import ScopedKeyFactory
from jdlib.caching.local import LocalCache
from jdlib.context import Principal, PrincipalKind, TenantContext
from jdlib.control.enums import PlacementStrategy
from jdlib.credentials.rotation import VersionedSecretProvider
from jdlib.data.postgres import PostgresConnector
from jdlib.data.registry import ConnectorRegistry
from jdlib.persistence.secrets import MemorySecretProvider
from jdlib.query.compiler import QueryCompiler
from jdlib.query.errors import CrossTenantQueryError
from jdlib.query.safety import IdentifierPolicy
from jdlib.query.specification import Filter, QuerySpecification
from jdlib.resources.errors import ResourceHydrationError
from jdlib.resources.handle import ResourceHandle
from jdlib.resources.resolver import ResourceResolver
from jdlib.security.context import AuthMethod, SecurityContext, security_context_scope
from jdlib.security.tracing import FORBIDDEN_SPAN_ATTRIBUTES, is_sensitive_key
from tests.support.context_fakes import CallableClock

TENANT_ID = uuid.UUID("11111111-1111-1111-1111-111111111111")
HANDLE = "db/main"
TARGET = "postgresql+asyncpg://user@host:5432/db"  # noqa: S105 - a target, not a secret
SECRET_VALUE = "s3cr3t-material-that-must-not-be-exported"


class _RecordingSpan:
    def __init__(self, name: str, attributes: dict[str, Any]) -> None:
        self.name = name
        self.attributes = dict(attributes)
        self.ended = False

    def set_attribute(self, key: str, value: object) -> None:
        self.attributes[key] = value

    def end(self, *, status: str | None = None) -> None:
        self.ended = True


class _RecordingTracer:
    """Stands in for the exporter. Records what would have been exported."""

    def __init__(self, *, fail: bool = False) -> None:
        self.spans: list[_RecordingSpan] = []
        self._fail = fail

    def start_span(self, name: str, attributes: dict[str, Any]) -> _RecordingSpan:
        if self._fail:
            raise RuntimeError("collector unavailable")
        span = _RecordingSpan(name, attributes)
        self.spans.append(span)
        return span

    @property
    def names(self) -> list[str]:
        return [span.name for span in self.spans]

    @property
    def attributes(self) -> dict[str, Any]:
        merged: dict[str, Any] = {}
        for span in self.spans:
            merged.update(span.attributes)
        return merged


def _context() -> SecurityContext:
    tenant = TenantContext(
        tenant_id=TENANT_ID,
        tenant_slug="acme",
        strategy=PlacementStrategy.SHARED,
        principal=Principal(kind=PrincipalKind.USER, id=uuid.uuid4()),
        request_id="req-1",
        correlation_id="corr-1",
        trace_id=None,
    )
    return SecurityContext.from_tenant_context(tenant=tenant, auth_method=AuthMethod.SERVICE)


def _policy() -> IdentifierPolicy:
    return IdentifierPolicy(
        tables={"events": ("id", "kind", "occurred_at")},
        tenant_scoped=("events",),
        tenant_plane=("projects",),
    )


def _spec(value: str = "hire") -> QuerySpecification:
    return QuerySpecification(
        table="events",
        columns=["id", "kind"],
        filters=[Filter(column="kind", operator="eq", value=value)],
        limit=10,
    )


def _cache() -> LocalCache:
    return LocalCache(
        keys=ScopedKeyFactory(), clock=CallableClock(datetime(2026, 9, 24, tzinfo=UTC))
    )


def _resolver(tracer: _RecordingTracer) -> ResourceResolver:
    return ResourceResolver(
        secrets=VersionedSecretProvider(MemorySecretProvider({HANDLE: TARGET})),
        cache=_cache(),
        tracer=tracer,
    )


# --- one span per boundary, at the boundary --------------------------------------------------


async def test_hydration_opens_exactly_one_span_at_its_boundary() -> None:
    tracer = _RecordingTracer()
    resolver = _resolver(tracer)

    with security_context_scope(_context()):
        await resolver.hydrate(ResourceHandle(HANDLE))

    assert tracer.names == ["resources.hydrate"]
    assert tracer.attributes["security.result"] == "hydrated"


def test_query_compilation_opens_exactly_one_span_at_its_boundary() -> None:
    """The allow-list, the parsing and the rendering are helpers: none of them gets a span."""
    tracer = _RecordingTracer()
    compiler = QueryCompiler(policy=_policy(), tracer=tracer)

    compiler.compile(_spec(), context=_context())

    assert tracer.names == ["query.compile"]
    assert tracer.attributes["security.result"] == "compiled"


def test_credential_resolution_opens_exactly_one_span_at_its_boundary() -> None:
    tracer = _RecordingTracer()
    provider = VersionedSecretProvider(
        MemorySecretProvider({HANDLE: SECRET_VALUE}), tracer=tracer
    )

    provider.resolve(HANDLE)

    assert tracer.names == ["credentials.resolve"]
    assert tracer.attributes["security.result"] == "resolved"


def test_connector_acquisition_opens_exactly_one_span_at_its_boundary() -> None:
    tracer = _RecordingTracer()
    registry = ConnectorRegistry(tracer=tracer)
    name = registry.register(PostgresConnector)

    registry.build(name)

    assert tracer.names == ["connector.acquire"]
    assert tracer.attributes["security.backend"] == name


# --- a refusal lands on the boundary's own span ----------------------------------------------


async def test_a_refusal_is_recorded_on_the_same_span_and_still_fails_closed() -> None:
    tracer = _RecordingTracer()
    resolver = _resolver(tracer)

    with pytest.raises(ResourceHydrationError):
        await resolver.hydrate(ResourceHandle(HANDLE))  # no security context is bound

    assert tracer.names == ["resources.hydrate"]
    assert tracer.attributes["security.result"] == "refused"


def test_a_refused_query_is_recorded_on_the_same_span() -> None:
    tracer = _RecordingTracer()
    compiler = QueryCompiler(policy=_policy(), tracer=tracer)

    with pytest.raises(CrossTenantQueryError):
        compiler.compile(_spec(), context=None)

    assert tracer.names == ["query.compile"]
    assert tracer.attributes["security.result"] == "refused"


# --- telemetry safety, re-run over the new paths ---------------------------------------------


def test_no_bound_value_reaches_a_span_attribute() -> None:
    """Compiled values and resolved credentials are exactly what must not be exported."""
    tracer = _RecordingTracer()
    compiler = QueryCompiler(policy=_policy(), tracer=tracer)
    compiler.compile(_spec(value=SECRET_VALUE), context=_context())

    exported = " ".join(f"{key}={value}" for key, value in tracer.attributes.items())

    assert SECRET_VALUE not in exported

    credential_tracer = _RecordingTracer()
    provider = VersionedSecretProvider(
        MemorySecretProvider({HANDLE: SECRET_VALUE}), tracer=credential_tracer
    )
    provider.resolve(HANDLE)
    exported = " ".join(
        f"{key}={value}" for key, value in credential_tracer.attributes.items()
    )

    assert SECRET_VALUE not in exported
    assert TARGET not in exported


def test_every_attribute_is_namespaced_and_none_is_forbidden_or_sensitive() -> None:
    tracer = _RecordingTracer()
    compiler = QueryCompiler(policy=_policy(), tracer=tracer)
    compiler.compile(_spec(), context=_context())

    for key in tracer.attributes:
        assert key not in FORBIDDEN_SPAN_ATTRIBUTES
        assert not is_sensitive_key(key)
        assert key.startswith("security."), key


# --- and the machinery's own guarantees still hold over the new paths ------------------------


async def test_the_new_boundaries_are_inert_without_a_tracer() -> None:
    resolver = ResourceResolver(
        secrets=VersionedSecretProvider(MemorySecretProvider({HANDLE: TARGET})),
        cache=_cache(),
    )

    with security_context_scope(_context()):
        target = await resolver.hydrate(ResourceHandle(HANDLE))

    assert target.target == TARGET


def test_a_failing_tracer_does_not_fail_the_operation() -> None:
    """A collector outage is not a security event, and must not become one."""
    tracer = _RecordingTracer(fail=True)
    compiler = QueryCompiler(policy=_policy(), tracer=tracer)

    compiled = compiler.compile(_spec(), context=_context())

    assert compiled.parameters
    assert tracer.spans == []
