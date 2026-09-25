"""Doubles for the graph layer, in one place so two test files cannot drift apart.

The driver double is shaped like the async driver rather than like our adapter: ``session()``
returns an async context manager, ``run()`` awaits, and a transaction is begun from the session
and ended with a commit or a rollback. That shape is the contract the adapter is written
against, so a change in the adapter's expectations shows up here first.
"""

from __future__ import annotations

import asyncio
import uuid
from typing import Any

from jdlib.context import Principal, PrincipalKind, TenantContext
from jdlib.control.enums import PlacementStrategy
from jdlib.credentials import ResolvedSecret, SecretRef, SecretVersion
from jdlib.graph import GraphQuery
from jdlib.security.context import AuthMethod, SecurityContext

TENANT_ID = uuid.UUID("11111111-1111-1111-1111-111111111111")
OTHER_TENANT_ID = uuid.UUID("22222222-2222-2222-2222-222222222222")
RESOLVED = "placeholder-for-tests"


def graph_context(tenant_id: uuid.UUID = TENANT_ID) -> SecurityContext:
    """An authenticated context for a tenant, built the way the rest of the tree builds one."""
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


class RecordingProvider:
    """The credential chain's shape: a reference in, a resolved value out."""

    def __init__(self) -> None:
        self.refs: list[SecretRef] = []

    def resolve(self, ref: SecretRef) -> ResolvedSecret:
        self.refs.append(ref)
        return ResolvedSecret(ref=ref, version=SecretVersion("1"), value=RESOLVED)


class RecordingClient:
    """A client that keeps what it was asked to run, and answers with what it was given."""

    def __init__(self, rows: list[dict[str, Any]] | None = None) -> None:
        self.queries: list[GraphQuery] = []
        self.rows = rows if rows is not None else []

    async def open(self, *, context: SecurityContext) -> None: ...

    async def close(self) -> None: ...

    async def health(self) -> bool:
        return True

    async def run(
        self, *, query: GraphQuery, context: SecurityContext
    ) -> list[dict[str, Any]]:
        self.queries.append(query)
        return list(self.rows)


class FakeResult:
    def __init__(self, rows: list[dict[str, Any]]) -> None:
        self._rows = rows

    async def data(self) -> list[dict[str, Any]]:
        return list(self._rows)


class FakeTransaction:
    """One transaction on a fake driver: records statements, and how it ended."""

    def __init__(self, driver: FakeDriver) -> None:
        self._driver = driver
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.committed = False
        self.rolled_back = False
        #: A commit that fails is the case the retry rule exists for: the server may have applied
        #: the transaction before the error arrived.
        self.commit_error: BaseException | None = None

    async def run(self, text: str, parameters: dict[str, Any] | None = None) -> FakeResult:
        self.calls.append((text, dict(parameters or {})))
        if self._driver.error is not None:
            raise self._driver.error
        return FakeResult(self._driver.rows)

    async def commit(self) -> None:
        if self.commit_error is not None:
            raise self.commit_error
        self.committed = True

    async def rollback(self) -> None:
        self.rolled_back = True


class FakeSession:
    def __init__(self, driver: FakeDriver) -> None:
        self._driver = driver

    async def __aenter__(self) -> FakeSession:
        return self

    async def __aexit__(self, *exc: object) -> bool:
        return False

    async def begin_transaction(self, **kwargs: Any) -> FakeTransaction:
        self._driver.begin_kwargs = kwargs
        self._driver.transaction = FakeTransaction(self._driver)
        return self._driver.transaction

    async def run(
        self, text: str, parameters: dict[str, Any] | None = None, **kwargs: Any
    ) -> FakeResult:
        self._driver.calls.append((text, dict(parameters or {}), kwargs))
        if self._driver.delay:
            await asyncio.sleep(self._driver.delay)
        if self._driver.error is not None:
            raise self._driver.error
        return FakeResult(self._driver.rows)

    async def close(self) -> None:
        self._driver.session_closed = True


class FakeDriver:
    """Shaped like the async driver: session() is an async context manager, run() awaits."""

    def __init__(
        self,
        *,
        rows: list[dict[str, Any]] | None = None,
        error: BaseException | None = None,
        delay: float = 0.0,
        reachable: bool = True,
    ) -> None:
        self.rows = rows if rows is not None else [{"id": "u1"}]
        self.error = error
        self.delay = delay
        self.reachable = reachable
        self.calls: list[tuple[str, dict[str, Any], dict[str, Any]]] = []
        self.closed = False
        self.database: str | None = None
        self.transaction: FakeTransaction | None = None
        self.begin_kwargs: dict[str, Any] = {}
        self.session_closed = False

    def session(self, *, database: str | None = None) -> FakeSession:
        self.database = database
        return FakeSession(self)

    async def verify_connectivity(self) -> None:
        if not self.reachable:
            raise RuntimeError("the server did not answer")

    async def close(self) -> None:
        self.closed = True


class DriverFactory:
    """The injected factory, keeping the kwargs the adapter passed."""

    def __init__(self, driver: FakeDriver) -> None:
        self.driver = driver
        self.uri: str | None = None
        self.kwargs: dict[str, Any] = {}

    def __call__(self, uri: str, **kwargs: Any) -> FakeDriver:
        self.uri = uri
        self.kwargs = kwargs
        return self.driver
