"""Connector framework (successor Phase 6). RED first.

The reliability inventory settled what this phase may and may not build. JDLib already
implements two-layer timeouts, bounded retry with full-jitter backoff and fail-closed
exhaustion adapter-locally, and the public retryability contract is_retryable() has no caller
anywhere in src/. So ConnectionPolicy EXTENDS that idiom - the same validated frozen config,
the same injected clock and sleeper, the same "raise the typed unavailable error on the last
attempt" - and it adds the two things the inventory recorded as genuinely absent: circuit
breaking and half-open recovery. No ResilienceManager, no second framework.

The two gate tests are the ones the phase exists for:

* a connector that cannot verify it received an AUTHORIZED context refuses to open;
* async discipline is proven, not asserted in a comment - a synchronous implementation fails
  the contract, by inspecting the interface rather than by racing a timer.
"""

from __future__ import annotations

import inspect
import uuid
from datetime import UTC, datetime, timedelta

import pytest

from jdlib.context import Principal, PrincipalKind, TenantContext
from jdlib.control.enums import PlacementStrategy
from jdlib.data.capabilities import ConnectorCapabilities
from jdlib.data.connector import AuthorizationRefusedError, DataConnector
from jdlib.data.errors import CircuitOpenError, ConnectorError, ConnectorTimeoutError
from jdlib.data.policy import ConnectionPolicy
from jdlib.data.registry import ConnectorRegistry
from jdlib.resources.connection import ConnectionConfig
from jdlib.security.context import AuthMethod, SecurityContext, security_context_scope

TENANT_ID = uuid.UUID("11111111-1111-1111-1111-111111111111")
OTHER_TENANT_ID = uuid.UUID("22222222-2222-2222-2222-222222222222")
NOW = datetime(2026, 9, 24, 12, 0, 0, tzinfo=UTC)


async def _no_sleep(seconds: float) -> None:
    """Sleeping is injected, so retry tests need no real time."""


class _Clock:
    def __init__(self) -> None:
        self.now = NOW

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += timedelta(seconds=seconds)


def _context(tenant_id: uuid.UUID = TENANT_ID) -> SecurityContext:
    principal = Principal(kind=PrincipalKind.USER, id=uuid.uuid4())
    tenant = TenantContext(
        tenant_id=tenant_id,
        tenant_slug="acme",
        strategy=PlacementStrategy.SHARED,
        principal=principal,
        request_id="req-1",
        correlation_id="corr-1",
        trace_id=None,
    )
    return SecurityContext.from_tenant_context(tenant=tenant, auth_method=AuthMethod.SERVICE)


def _config(tenant_id: uuid.UUID = TENANT_ID) -> ConnectionConfig:
    return ConnectionConfig(
        handle="db-tenant-acme",
        target="postgres://user:secret-password@host/acme",
        credential_version="1",
        tenant_id=str(tenant_id),
    )


class _StubConnector:
    """The reference double every implementation is compared against (ADR-6).

    Capabilities are a class attribute because they are static facts about the engine: the
    registry validates a connector TYPE at startup, before any configuration exists to
    instantiate one with.
    """

    capabilities = ConnectorCapabilities(name="stub", reads=True, writes=False, transactions=False)

    def __init__(self, fail_times: int = 0, slow: bool = False) -> None:
        self.fail_times = fail_times
        self.slow = slow
        self.attempts = 0
        self.opened = False

    async def open(self, *, target: ConnectionConfig, context: SecurityContext) -> None:
        tenant = context.require_tenant()
        if str(tenant.tenant_id) != target.tenant_id:
            raise AuthorizationRefusedError(
                f"connector stub: the authorized context is for tenant {tenant.tenant_id}, "
                f"but the target belongs to {target.tenant_id}"
            )
        self.opened = True

    async def close(self) -> None:
        self.opened = False

    async def health(self) -> bool:
        return self.opened

    async def execute(self, *, statement: str, params: tuple = ()) -> list[dict]:
        self.attempts += 1
        if self.attempts <= self.fail_times:
            raise ConnectorError("stub: transient failure", transient=True)
        return [{"ok": True}]


# --- the gate's first item: an unauthorized context refuses to open -------------------------


async def test_a_connector_refuses_to_open_on_a_tenant_mismatch() -> None:
    connector = _StubConnector()

    with (
        security_context_scope(_context(OTHER_TENANT_ID)),
        pytest.raises(AuthorizationRefusedError),
    ):
        await connector.open(target=_config(TENANT_ID), context=_context(OTHER_TENANT_ID))

    assert connector.opened is False


async def test_a_connector_opens_for_the_authorized_tenant() -> None:
    connector = _StubConnector()
    context = _context()

    with security_context_scope(context):
        await connector.open(target=_config(), context=context)

    assert connector.opened is True


# --- the gate's second item: async discipline, proven by inspection -------------------------


def test_the_connector_protocol_is_asynchronous_throughout() -> None:
    """ADR-14: an implementation that blocks the event loop fails the contract, not a review."""
    for name in ("open", "close", "health", "execute"):
        method = getattr(DataConnector, name)
        assert inspect.iscoroutinefunction(method), f"{name} must be async"


def test_a_synchronous_implementation_fails_the_contract() -> None:
    class Blocking:
        @property
        def capabilities(self) -> ConnectorCapabilities:
            return ConnectorCapabilities(
                name="blocking", reads=True, writes=True, transactions=False
            )

        def open(self, *, target, context) -> None:  # pragma: no cover - must never be called
            return None

        def close(self) -> None:  # pragma: no cover
            return None

        def health(self) -> bool:  # pragma: no cover
            return True

        def execute(self, *, statement: str, params: tuple = ()) -> list:  # pragma: no cover
            return []

    from jdlib.data.contract import assert_connector_contract

    problems = assert_connector_contract(Blocking)

    assert problems, "a synchronous connector must not satisfy the contract"
    assert any("open" in problem for problem in problems)


# --- the policy: the existing idiom, plus what the inventory said was missing --------------


def test_a_non_positive_timeout_is_refused() -> None:
    for bad in ({"connect_timeout": 0}, {"statement_timeout": -1}):
        with pytest.raises(ConnectorError):
            ConnectionPolicy(**bad)


async def test_a_retry_succeeds_within_the_attempt_budget() -> None:
    connector = _StubConnector(fail_times=2)
    policy = ConnectionPolicy(max_attempts=3)

    result = await policy.run(connector, statement="select 1", sleeper=_no_sleep)

    assert result == [{"ok": True}]
    assert connector.attempts == 3


async def test_exhausting_the_attempt_budget_raises_rather_than_returning_nothing() -> None:
    connector = _StubConnector(fail_times=5)
    policy = ConnectionPolicy(max_attempts=2)

    with pytest.raises(ConnectorError):
        await policy.run(connector, statement="select 1", sleeper=_no_sleep)

    assert connector.attempts == 2


def test_a_timeout_is_raised_as_a_timeout() -> None:
    policy = ConnectionPolicy(statement_timeout=1)

    with pytest.raises(ConnectorTimeoutError):
        policy.raise_for_timeout(elapsed=2.5, operation="execute")


async def test_the_circuit_opens_after_repeated_failures() -> None:
    """ABSENT per the reliability inventory; the reason this phase adds anything at all."""
    clock = _Clock()
    breaker = ConnectionPolicy(failure_threshold=3, reset_after=timedelta(seconds=30)).breaker(
        clock
    )
    connector = _StubConnector(fail_times=99)

    for _ in range(3):
        with pytest.raises(ConnectorError):
            await breaker.run(connector, sleeper=_no_sleep)

    with pytest.raises(CircuitOpenError):
        await breaker.run(connector, sleeper=lambda seconds: None)


async def test_the_circuit_half_opens_after_the_reset_window_and_closes_on_success() -> None:
    clock = _Clock()
    breaker = ConnectionPolicy(failure_threshold=2, reset_after=timedelta(seconds=30)).breaker(
        clock
    )
    failing = _StubConnector(fail_times=99)

    for _ in range(2):
        with pytest.raises(ConnectorError):
            await breaker.run(failing, sleeper=_no_sleep)
    with pytest.raises(CircuitOpenError):
        await breaker.run(failing, sleeper=_no_sleep)

    clock.advance(31)

    healthy = _StubConnector()
    assert await breaker.run(healthy, sleeper=_no_sleep) == [{"ok": True}]
    assert await breaker.run(healthy, sleeper=_no_sleep) == [{"ok": True}]


# --- the registry: validated at startup, not at first use (ADR-6) ---------------------------


def test_a_duplicate_connector_name_is_refused_at_registration() -> None:
    registry = ConnectorRegistry()
    registry.register(_StubConnector)

    with pytest.raises(ConnectorError):
        registry.register(_StubConnector)


def test_a_registration_without_capabilities_is_refused() -> None:
    class Nameless:
        @property
        def capabilities(self):  # pragma: no cover - must never be reached
            raise AssertionError("capabilities must be declared, not raised")

    registry = ConnectorRegistry()

    with pytest.raises(ConnectorError):
        registry.register(Nameless)


def test_the_registry_builds_a_registered_connector_and_refuses_an_unknown_name() -> None:
    registry = ConnectorRegistry()
    registry.register(_StubConnector)

    assert isinstance(registry.build("stub"), _StubConnector)
    with pytest.raises(ConnectorError):
        registry.build("nosuch")
