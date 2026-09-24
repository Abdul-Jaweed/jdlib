"""Adversarial review of the successor capabilities (Phase 14).

The directive's red-team areas, applied to what §4-§12 built rather than to the older core:

* identity      - can a job or a credential be made to act as something it is not?
* tenant
  isolation     - can any new path reach another tenant's data or cache entry?
* authorization - can a delegated privilege be replayed or widened?
* hydration     - can a resolved target outlive its rotation, or leak across tenants?
* query         - can an identifier, an operator or a value escape the allow-list?
* cryptography  - can a signature be truncated, re-encoded or swapped?
* external
  state         - what does a hostile key or handle look like?

Each test names the attack rather than the API, because the point of this file is to be read by
someone asking "what did you try?". Where an attack is expected to be refused by construction,
the test asserts the *mechanism* (the predicate is present, the parameter is bound, the value is
absent from the text) instead of just an exception type.
"""

from __future__ import annotations

import base64
import json
import uuid
from datetime import UTC, datetime, timedelta

import pytest

from jdlib.caching.keys import ScopedKeyFactory
from jdlib.caching.local import LocalCache
from jdlib.config import ContextConfig
from jdlib.context import (
    EnvelopeCodec,
    Principal,
    PrincipalKind,
    PrivilegeContext,
    PrivilegeKind,
    TenantContext,
    TenantRecord,
    validate_delegation,
)
from jdlib.control.enums import PlacementStrategy, TenantStatus
from jdlib.credentials.errors import CredentialVersionRetiredError
from jdlib.credentials.refs import SecretRef
from jdlib.credentials.rotation import VersionedSecretProvider
from jdlib.errors import DelegationRefusedError, TenantNotFound
from jdlib.persistence.secrets import MemorySecretProvider
from jdlib.query.compiler import QueryCompiler
from jdlib.query.errors import CrossTenantQueryError, QueryParseError
from jdlib.query.safety import IdentifierPolicy
from jdlib.query.specification import Filter, QuerySpecification, SortDirection, SortKey
from jdlib.security.context import AuthMethod, SecurityContext
from jdlib.tenancy.job_envelope import (
    EnvelopeForgeryError,
    JobDispatcher,
    JobEnvelope,
)
from jdlib.tenancy.jobs import ContextPropagator
from tests.support.context_fakes import (
    CallableClock,
    DictTenants,
    EntitlementsStub,
    ServabilityStub,
    StaticPrincipals,
)

TENANT_A = uuid.UUID("aaaaaaaa-0000-0000-0000-000000000001")
TENANT_B = uuid.UUID("bbbbbbbb-0000-0000-0000-000000000002")
PRINCIPAL_ID = uuid.UUID("33333333-3333-3333-3333-333333333333")
NOW = datetime(2026, 9, 24, 12, 0, 0, tzinfo=UTC)
LIFETIME = timedelta(minutes=5)
KEY = "adversarial-suite-key"


def _policy() -> IdentifierPolicy:
    return IdentifierPolicy(
        tables={"events": ("id", "tenant_id", "kind", "occurred_at")},
        tenant_scoped=("events",),
        tenant_plane=("projects", "audit_events"),
    )


def _context(tenant_id: uuid.UUID = TENANT_A) -> SecurityContext:
    tenant = TenantContext(
        tenant_id=tenant_id,
        tenant_slug="acme",
        strategy=PlacementStrategy.SHARED,
        principal=Principal(kind=PrincipalKind.USER, id=PRINCIPAL_ID),
        request_id="req-1",
        correlation_id="corr-1",
        trace_id=None,
    )
    return SecurityContext.from_tenant_context(tenant=tenant, auth_method=AuthMethod.SERVICE)


def _spec(**overrides) -> QuerySpecification:
    values: dict[str, object] = {"table": "events", "columns": ["id", "kind"], "limit": 10}
    values.update(overrides)
    return QuerySpecification(**values)  # type: ignore[arg-type]


# --- query: identifier and operator escapes ---------------------------------------------------

# Latin 'a' (U+0061) versus Cyrillic 'а' (U+0430). They render identically in most fonts, so
# an allow-list that matched on "looks like" would accept the second one.
HOMOGLYPH_COLUMN = "occurred_\u0430t"


@pytest.mark.parametrize(
    "hostile_table",
    [
        "events; DROP TABLE events",
        "events--",
        "events /*x*/",
        "EVENTS",
        "events ",
        "events\t",
        " public.events",
        "events\u0000",
        "еvents",  # Cyrillic 'е'
    ],
)
def test_a_hostile_table_identifier_is_refused_at_parse_time(hostile_table: str) -> None:
    compiler = QueryCompiler(policy=_policy())

    with pytest.raises(QueryParseError):
        compiler.compile(_spec(table=hostile_table), context=_context())


@pytest.mark.parametrize(
    "hostile_column",
    [
        "id; --",
        "id, secret",
        "*",
        "count(*)",
        "id::text",
        HOMOGLYPH_COLUMN,
        "ID",
        "",
    ],
)
def test_a_hostile_column_identifier_is_refused_at_parse_time(hostile_column: str) -> None:
    compiler = QueryCompiler(policy=_policy())

    with pytest.raises(QueryParseError):
        compiler.compile(_spec(columns=[hostile_column]), context=_context())


@pytest.mark.parametrize(
    "hostile_sort",
    ["id; --", "id DESC, secret", "1", HOMOGLYPH_COLUMN],
)
def test_a_hostile_sort_key_is_refused_at_parse_time(hostile_sort: str) -> None:
    compiler = QueryCompiler(policy=_policy())

    with pytest.raises(QueryParseError):
        compiler.compile(_spec(order_by=[SortKey(column=hostile_sort)]), context=_context())


@pytest.mark.parametrize("hostile_operator", ["=", "eq OR 1=1", "eq; DROP", "LIKE", "in(", ""])
def test_an_operator_outside_the_allow_list_is_refused_at_parse_time(
    hostile_operator: str,
) -> None:
    compiler = QueryCompiler(policy=_policy())

    with pytest.raises(QueryParseError):
        compiler.compile(
            _spec(filters=[Filter(column="kind", operator=hostile_operator, value="x")]),
            context=_context(),
        )


def test_a_tenant_routed_table_cannot_be_queried_through_the_compiler() -> None:
    """ADR-1: the tenant plane stays on the repository, so this path must not reach it."""
    compiler = QueryCompiler(policy=_policy())

    for table in ("projects", "audit_events"):
        with pytest.raises(QueryParseError):
            compiler.compile(_spec(table=table), context=_context())


def test_a_caller_supplied_tenant_filter_cannot_replace_the_scope_predicate() -> None:
    """The attack: filter on tenant_id yourself and hope the compiler defers to you."""
    compiler = QueryCompiler(policy=_policy())
    spec = _spec(filters=[Filter(column="tenant_id", operator="eq", value=str(TENANT_B))])

    compiled = compiler.compile(spec, context=_context(TENANT_A))
    text = compiled.text.lower()

    # Two predicates, and the caller's value is a bound parameter - never text - so the
    # scope predicate survives and the other tenant's rows simply cannot match.
    assert text.count("tenant_id") == 2
    assert str(TENANT_A) in compiled.parameters.values()
    assert str(TENANT_B) not in compiled.text
    assert str(TENANT_B) in compiled.parameters.values()


def test_the_scope_predicate_is_present_for_every_compiled_query() -> None:
    compiler = QueryCompiler(policy=_policy())

    for spec in (
        _spec(),
        _spec(filters=[Filter(column="kind", operator="eq", value="x")]),
        _spec(order_by=[SortKey(column="id", direction=SortDirection.DESC)]),
    ):
        compiled = compiler.compile(spec, context=_context())
        assert "tenant_id" in compiled.text.lower()


def test_bind_values_never_appear_in_the_rendered_statement() -> None:
    hostile = "'; DROP TABLE events; --"
    compiler = QueryCompiler(policy=_policy())

    compiled = compiler.compile(
        _spec(filters=[Filter(column="kind", operator="eq", value=hostile)]), context=_context()
    )

    assert hostile not in compiled.text
    assert hostile in compiled.parameters.values()


def test_compiling_without_a_context_is_refused_rather_than_defaulted() -> None:
    compiler = QueryCompiler(policy=_policy())

    with pytest.raises(CrossTenantQueryError):
        compiler.compile(_spec(), context=None)


# --- cryptography: signatures ------------------------------------------------------------------


def _world() -> tuple[EnvelopeCodec, TenantRecord, CallableClock]:
    clock = CallableClock(NOW)
    codec = EnvelopeCodec(config=ContextConfig(signing_key=KEY, envelope_ttl=LIFETIME), clock=clock)
    record = TenantRecord(
        id=TENANT_A, slug="acme", status=TenantStatus.ACTIVE, strategy=PlacementStrategy.SHARED
    )
    return codec, record, clock


def _token(
    codec: EnvelopeCodec,
    clock: CallableClock,
    tenant_id: uuid.UUID = TENANT_A,
    job_id: str = "job-0001",
) -> str:
    tenant = TenantContext(
        tenant_id=tenant_id,
        tenant_slug="acme",
        strategy=PlacementStrategy.SHARED,
        principal=Principal(kind=PrincipalKind.SERVICE_ACCOUNT, id=PRINCIPAL_ID),
        request_id="req-1",
        correlation_id="corr-1",
        trace_id=None,
    )
    return JobEnvelope.issue(
        codec=codec, context=tenant, job_id=job_id, ttl=LIFETIME, key=KEY, clock=clock
    ).to_token()


def test_a_truncated_signature_is_refused() -> None:
    codec, _record, clock = _world()
    wire = _token(codec, clock)
    payload = json.loads(base64.urlsafe_b64decode(wire.encode()).decode())
    payload["signature"] = payload["signature"][:16]

    with pytest.raises(EnvelopeForgeryError):
        JobEnvelope.parse(
            base64.urlsafe_b64encode(json.dumps(payload).encode()).decode(), key=KEY
        )


def test_a_valid_signature_over_re_encoded_fields_is_refused() -> None:
    """Re-encoding the payload keeps the signature string but changes what it covers."""
    codec, _record, clock = _world()
    wire = _token(codec, clock)
    payload = json.loads(base64.urlsafe_b64decode(wire.encode()).decode())
    payload["expires_at"] = (NOW + timedelta(days=3650)).isoformat()

    with pytest.raises(EnvelopeForgeryError):
        JobEnvelope.parse(
            base64.urlsafe_b64encode(json.dumps(payload).encode()).decode(), key=KEY
        )


def test_swapping_the_tenant_token_inside_a_valid_envelope_is_refused() -> None:
    codec, _record, clock = _world()
    mine = _token(codec, clock, TENANT_A)
    theirs = _token(codec, clock, TENANT_B)
    payload = json.loads(base64.urlsafe_b64decode(mine.encode()).decode())
    payload["token"] = json.loads(base64.urlsafe_b64decode(theirs.encode()).decode())["token"]

    with pytest.raises(EnvelopeForgeryError):
        JobEnvelope.parse(
            base64.urlsafe_b64encode(json.dumps(payload).encode()).decode(), key=KEY
        )


async def test_a_job_token_for_another_tenant_cannot_be_replayed_as_mine() -> None:
    """Both are authentic; the point is that the envelope's own scope decides, not the caller."""
    codec, record, clock = _world()
    dispatcher = JobDispatcher(
        propagator=ContextPropagator(
            codec=codec,
            principals=StaticPrincipals({PRINCIPAL_ID}),
            tenants=DictTenants([record]),
            servability=ServabilityStub(records={TENANT_A: record}),
            entitlements=EntitlementsStub({(PRINCIPAL_ID, TENANT_A)}),
        ),
        key=KEY,
        clock=clock,
    )
    seen: list[uuid.UUID] = []

    async def handler() -> str:
        from jdlib.context import current_tenant

        seen.append(current_tenant().tenant_id)
        return "ran"

    assert await dispatcher.execute(_token(codec, clock, TENANT_A), handler) == "ran"
    assert seen == [TENANT_A]

    # A distinct job id, or this would be a replay rather than the attack under test: replay
    # detection runs before the tenant chain, so reusing job-0001 would prove something else
    # (worth knowing - the ordering is itself a defence). The envelope here is authentic and
    # unspent; the tenant is simply not one this dispatcher can resolve.
    with pytest.raises(TenantNotFound):
        await dispatcher.execute(_token(codec, clock, TENANT_B, "job-0002"), handler)

    assert seen == [TENANT_A]


# --- authorization: delegation replay -----------------------------------------------------------


def _delegation(**overrides) -> PrivilegeContext:
    values: dict[str, object] = {
        "kind": PrivilegeKind.DELEGATION,
        "delegation_id": "deleg-0001",
        "capability": "read:events",
        "justification": "nightly reconciliation",
        "actor": Principal(kind=PrincipalKind.USER, id=uuid.uuid4(), tenant_id=TENANT_A),
        "issued_at": NOW - timedelta(minutes=1),
        "expires_at": NOW + timedelta(minutes=5),
    }
    values.update(overrides)
    return PrivilegeContext(**values)  # type: ignore[arg-type]


def test_a_replayed_delegation_is_refused_even_for_a_different_capability() -> None:
    """The attack: reuse the identifier and hope the replay check is per-capability."""
    seen = {"deleg-0001"}

    with pytest.raises(DelegationRefusedError):
        validate_delegation(
            _delegation(capability="write:events"),
            capability="write:events",
            target_tenant_id=TENANT_A,
            now=NOW,
            seen=seen,
        )


def test_a_suspended_actor_makes_its_delegation_unusable() -> None:
    with pytest.raises(DelegationRefusedError):
        validate_delegation(
            _delegation(),
            capability="read:events",
            target_tenant_id=TENANT_A,
            now=NOW,
            is_suspended=lambda actor_id: True,
        )


def test_an_operator_privilege_is_not_silently_treated_as_a_delegation() -> None:
    """Pass-through is the ADR's explicit choice, so this asserts the choice, not a refusal."""
    operator = PrivilegeContext(
        kind=PrivilegeKind.OPERATOR,
        capability="read:events",
        justification="platform incident",
        actor=Principal(kind=PrincipalKind.USER, id=uuid.uuid4(), tenant_id=TENANT_A),
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
    )

    assert (
        validate_delegation(
            operator, capability="read:events", target_tenant_id=TENANT_A, now=NOW
        )
        is operator
    )


# --- credentials and hydration: isolation across handles and tenants ---------------------------


def test_resolving_one_handle_never_serves_another_handles_value() -> None:
    provider = VersionedSecretProvider(
        MemorySecretProvider({"db/analytics": "analytics-secret", "db/reports": "reports-secret"})
    )

    assert provider.resolve("db/analytics").value == "analytics-secret"
    assert provider.resolve("db/reports").value == "reports-secret"


def test_a_retired_credential_version_cannot_be_pinned_after_rotation() -> None:
    provider = VersionedSecretProvider(MemorySecretProvider({"db/reports": "first"}))
    first = provider.current_version("db/reports")
    assert first is not None

    provider.rotate("db/reports", new_value="second", version="v2")

    with pytest.raises(CredentialVersionRetiredError):
        provider.resolve(SecretRef(handle="db/reports", version=first))


def test_a_rotated_credential_yields_a_different_cache_key_component() -> None:
    """This is what makes a stale target impossible rather than merely unlikely."""
    provider = VersionedSecretProvider(MemorySecretProvider({"db/reports": "first"}))
    before = provider.current_version("db/reports")

    provider.rotate("db/reports", new_value="second", version="v2")
    after = provider.current_version("db/reports")

    assert before is not None and after is not None
    assert str(before) != str(after)


def test_a_cache_entry_written_for_one_tenant_is_invisible_to_another() -> None:
    cache = LocalCache(keys=ScopedKeyFactory(), clock=CallableClock(NOW))
    cache.set(
        tenant=str(TENANT_A),
        namespace="resources",
        resource="db/reports",
        identifier="v1",
        value="tenant-a-target",
        ttl=300,
    )

    stolen = cache.get(
        tenant=str(TENANT_B), namespace="resources", resource="db/reports", identifier="v1"
    )
    mine = cache.get(
        tenant=str(TENANT_A), namespace="resources", resource="db/reports", identifier="v1"
    )

    assert stolen is None
    assert mine == "tenant-a-target"
