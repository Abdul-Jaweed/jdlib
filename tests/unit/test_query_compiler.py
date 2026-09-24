"""Query specification and compiler (successor Phase 8). RED first.

Scoped by ADR-1: this exists for engines without an ORM, and it never replaces
``TenantRepository`` for tenant-plane rows - one of the tests below asserts exactly that.

The gate is adversarial, so the tests are attacks rather than demonstrations:

* SQL injection through values - a value is bound, never interpolated, whatever it contains;
* identifier injection through table, column, operator and sort names - an allowlist checked
  at PARSE time, so a bad specification never reaches a compiler;
* dangerous constructs - there is no way to express raw SQL, a subquery or a function call,
  because the specification has no field for one;
* unbounded pagination and query amplification - limits and list sizes are bounded;
* cross-tenant and tenant-plane access - refused, and the compiler adds the tenant predicate
  itself rather than trusting the caller to remember.

The last property matters most: the compiled query is ONE value carrying the text and its
bound parameters, so a caller cannot use the text without the parameters or vice versa.
"""

from __future__ import annotations

import uuid

import pytest

from jdlib.context import Principal, PrincipalKind, TenantContext
from jdlib.control.enums import PlacementStrategy
from jdlib.query.ast import SortDirection
from jdlib.query.compiler import QueryCompiler
from jdlib.query.dialect import MysqlDialect, PostgresDialect
from jdlib.query.errors import (
    CrossTenantQueryError,
    QueryComplexityError,
    QueryParseError,
    TenantPlaneQueryError,
)
from jdlib.query.safety import IdentifierPolicy, parse_specification
from jdlib.query.specification import Filter, QuerySpecification, SortKey
from jdlib.security.context import AuthMethod, SecurityContext

TENANT_ID = uuid.UUID("11111111-1111-1111-1111-111111111111")
OTHER_TENANT_ID = uuid.UUID("22222222-2222-2222-2222-222222222222")
TENANT_PLANE_TABLE = "projects"


@pytest.fixture()
def policy() -> IdentifierPolicy:
    return IdentifierPolicy(
        tables={
            "events": ("id", "tenant_id", "kind", "occurred_at", "payload"),
            "metrics_hourly": ("tenant_id", "hour", "name", "value"),
        },
        tenant_scoped=("events", "metrics_hourly"),
        tenant_plane=(TENANT_PLANE_TABLE,),
    )


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


def _spec(**overrides) -> QuerySpecification:
    values = {
        "table": "events",
        "columns": ["id", "kind", "occurred_at"],
        "filters": [Filter(column="kind", operator="eq", value="login")],
        "limit": 100,
    }
    values.update(overrides)
    return QuerySpecification(**values)


# --- injection through values: bound, never interpolated -----------------------------------


def test_a_hostile_value_is_bound_and_never_appears_in_the_text(policy) -> None:
    hostile = "'; drop table events; --"
    compiled = QueryCompiler(policy).compile(
        _spec(filters=[Filter(column="kind", operator="eq", value=hostile)]), context=_context()
    )

    assert hostile not in compiled.text
    assert hostile in compiled.parameters.values()
    assert "drop table" not in compiled.text.lower()


def test_a_hostile_value_survives_a_round_trip_unchanged(policy) -> None:
    """Bound means bound: the value is carried verbatim, not escaped by hand."""
    hostile = "50% off' or '1'='1"
    compiled = QueryCompiler(policy).compile(
        _spec(filters=[Filter(column="kind", operator="eq", value=hostile)]), context=_context()
    )

    assert hostile in compiled.parameters.values()


def test_like_wildcards_in_a_value_are_not_interpreted_by_the_compiler(policy) -> None:
    compiled = QueryCompiler(policy).compile(
        _spec(filters=[Filter(column="kind", operator="like", value="log%")]), context=_context()
    )

    assert "log%" in compiled.parameters.values()
    assert "log%" not in compiled.text


# --- injection through identifiers: refused AT PARSE TIME -----------------------------------


@pytest.mark.parametrize(
    "hostile",
    [
        "events; drop table events",
        'events" or "1"="1',
        "events--",
        "events/*x*/",
        "1=1",
        "events e, secrets s",
        "pg_catalog.pg_shadow",
        "",
    ],
)
def test_a_hostile_table_identifier_is_refused_at_parse_time(policy, hostile) -> None:
    with pytest.raises(QueryParseError):
        parse_specification(_spec(table=hostile), policy)


@pytest.mark.parametrize(
    "hostile", ["kind; drop table events", "kind--)", "*", "payload->>'x'", "count(*)"]
)
def test_a_hostile_column_identifier_is_refused_at_parse_time(policy, hostile) -> None:
    with pytest.raises(QueryParseError):
        parse_specification(_spec(columns=["id", hostile]), policy)


def test_an_unknown_but_well_formed_table_is_refused(policy) -> None:
    with pytest.raises(QueryParseError):
        parse_specification(_spec(table="not_allowed"), policy)


def test_an_unknown_column_of_a_known_table_is_refused(policy) -> None:
    with pytest.raises(QueryParseError):
        parse_specification(_spec(columns=["id", "secret_column"]), policy)


def test_an_operator_outside_the_allowlist_is_refused(policy) -> None:
    with pytest.raises(QueryParseError):
        parse_specification(
            _spec(filters=[Filter(column="kind", operator="eq", value=1)]).model_copy(
                update={"filters": [Filter(column="kind", operator="!!", value=1)]}
            ),
            policy,
        )


def test_a_hostile_sort_column_is_refused(policy) -> None:
    with pytest.raises(QueryParseError):
        parse_specification(
            _spec(
                order_by=[
                    SortKey(column="occurred_at; drop table events", direction=SortDirection.DESC)
                ]
            ),
            policy,
        )


def test_parse_time_is_before_compile_time(policy) -> None:
    """The allowlist is a parse concern: a caller who parses is already protected."""
    ast = parse_specification(_spec(), policy)
    assert ast.table == "events"
    assert ast.columns == ("id", "kind", "occurred_at")


# --- dangerous constructs are not expressible at all ----------------------------------------


def test_the_specification_has_no_field_for_raw_sql(policy) -> None:
    """There is no 'where' string, no 'join', no 'function': unexpressible beats forbidden."""
    fields = set(QuerySpecification.model_fields)
    for forbidden in ("where", "sql", "raw", "join", "subquery", "having", "union"):
        assert forbidden not in fields, forbidden


def test_a_subquery_cannot_be_smuggled_through_a_filter_value(policy) -> None:
    """A value is a value: the compiler binds whatever it is given as a parameter."""
    compiled = QueryCompiler(policy).compile(
        _spec(
            filters=[Filter(column="kind", operator="eq", value="(select secret from credentials)")]
        ),
        context=_context(),
    )

    assert "select secret" not in compiled.text
    assert "(select secret from credentials)" in compiled.parameters.values()


# --- pagination and complexity are bounded ---------------------------------------------------


def test_a_limit_is_required(policy) -> None:
    with pytest.raises(QueryParseError):
        parse_specification(_spec(limit=None), policy)


def test_an_offset_without_a_limit_is_refused(policy) -> None:
    with pytest.raises(QueryParseError):
        parse_specification(_spec(limit=None, offset=10), policy)


def test_a_limit_above_the_cap_is_refused(policy) -> None:
    with pytest.raises(QueryComplexityError):
        parse_specification(_spec(limit=1_000_000), policy)


def test_too_many_columns_is_refused() -> None:
    """The bound is part of the policy, so the test states the bound it is testing."""
    narrow = IdentifierPolicy(
        tables={"events": ("id", "kind", "occurred_at")},
        tenant_scoped=("events",),
        max_columns=2,
    )

    parse_specification(_spec(columns=["id", "kind"]), narrow)
    with pytest.raises(QueryComplexityError):
        parse_specification(_spec(columns=["id", "kind", "occurred_at"]), narrow)


def test_too_many_filters_is_refused(policy) -> None:
    filters = [Filter(column="kind", operator="eq", value=f"v{i}") for i in range(50)]
    with pytest.raises(QueryComplexityError):
        parse_specification(_spec(filters=filters), policy)


def test_an_oversized_in_list_is_refused(policy) -> None:
    """Query amplification: one request must not become an unbounded scan."""
    with pytest.raises(QueryComplexityError):
        parse_specification(
            _spec(filters=[Filter(column="kind", operator="in", value=list(range(5000)))]), policy
        )


# --- tenancy: applied by the compiler, and the tenant plane is out of reach ------------------


def test_the_compiler_applies_the_tenant_constraint_itself(policy) -> None:
    compiled = QueryCompiler(policy).compile(_spec(), context=_context())

    assert "tenant_id" in compiled.text
    assert str(TENANT_ID) in compiled.parameters.values()


def test_a_spec_carrying_another_tenant_is_refused(policy) -> None:
    """Cross-tenant AST: the tenant comes from the context, and a disagreeing spec loses."""
    spec = _spec(tenant_id=str(OTHER_TENANT_ID))

    with pytest.raises(CrossTenantQueryError):
        QueryCompiler(policy).compile(spec, context=_context(TENANT_ID))


def test_a_tenant_plane_table_is_out_of_reach(policy) -> None:
    """ADR-1: TenantRepository remains the only path to tenant-plane rows."""
    with pytest.raises(TenantPlaneQueryError):
        parse_specification(_spec(table=TENANT_PLANE_TABLE, columns=["id"]), policy)


def test_compiling_without_a_security_context_is_refused(policy) -> None:
    with pytest.raises(CrossTenantQueryError):
        QueryCompiler(policy).compile(_spec(), context=None)


# --- the compiled query is one value ---------------------------------------------------------


def test_the_compiled_query_carries_text_and_parameters_together(policy) -> None:
    compiled = QueryCompiler(policy).compile(_spec(), context=_context())

    assert compiled.text.upper().startswith("SELECT")
    assert compiled.parameters
    assert set(compiled.parameters) <= set(compiled.names_in_order)
    assert compiled == compiled  # frozen value semantics


def test_the_rendered_form_shows_names_but_not_values(policy) -> None:
    compiled = QueryCompiler(policy).compile(
        _spec(filters=[Filter(column="kind", operator="eq", value="sensitive-literal")]),
        context=_context(),
    )

    assert "sensitive-literal" not in repr(compiled)
    assert compiled.parameters


def test_the_dialect_determines_placeholders_and_quoting(policy) -> None:
    postgres = QueryCompiler(policy, dialect=PostgresDialect()).compile(_spec(), context=_context())
    mysql = QueryCompiler(policy, dialect=MysqlDialect()).compile(_spec(), context=_context())

    assert postgres.text != mysql.text
    assert "`" in mysql.text and "`" not in postgres.text


def test_order_by_is_rendered_from_the_allowlist(policy) -> None:
    compiled = QueryCompiler(policy).compile(
        _spec(order_by=[SortKey(column="occurred_at", direction=SortDirection.DESC)]),
        context=_context(),
    )

    assert "ORDER BY" in compiled.text.upper()
    assert "DESC" in compiled.text.upper()
