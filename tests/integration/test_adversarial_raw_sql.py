"""Layer 2: the raw-SQL gate under attack, through the real enforcement path.

Phase 8 asks whether raw SQL is validated by parsing rather than by pattern
matching. The unit probes attempt the shapes; this file drives them through
`TenantSession.raw_sql` — the path an application actually calls, where the
tenant predicate is resolved against the ambient context — so an "allowed" case
proves the gate accepts a genuinely scoped statement and a refused case proves
policy refused it (a parse failure yields the same exception type on purpose:
fail closed either way, but the message distinguishes them).

The interesting attacks are the ones a text-matching gate would wave through: a
predicate that exists only inside a comment, a write hidden in a CTE, a UNION
branch with no predicate at all.
"""

from __future__ import annotations

import uuid

import pytest
import sqlalchemy as sa

from jdlib.context import Principal, PrincipalKind, TenantContext
from jdlib.control.enums import PlacementStrategy
from jdlib.errors import UnscopedRawSql
from jdlib.persistence.session import TenantSession

pytestmark = pytest.mark.integration

TENANT_A = uuid.UUID("00000000-0000-0000-0000-0000000000aa")


def _context() -> TenantContext:
    return TenantContext(
        tenant_id=TENANT_A,
        tenant_slug="acme",
        strategy=PlacementStrategy.SHARED,
        principal=Principal(kind=PrincipalKind.USER, id=uuid.uuid4()),
        request_id="req-adv",
        correlation_id="corr-adv",
    )


async def _session(session_factory) -> TenantSession:
    raw = session_factory()
    await raw.execute(sa.text('SET search_path TO "jt_test"'))
    return TenantSession(raw, _context())


async def test_a_genuinely_scoped_statement_is_accepted(session_factory) -> None:
    async with await _session(session_factory) as session:
        await session.raw_sql(
            sa.text("SELECT count(*) FROM invoices WHERE tenant_id = :tenant_id"),
            {"tenant_id": TENANT_A},
        )


@pytest.mark.parametrize(
    "sql",
    (
        # a predicate that exists only inside a comment: a regex would accept it
        "SELECT count(*) FROM invoices /* WHERE tenant_id = :tenant_id */",
        # a write hidden in a CTE behind a harmless-looking outer statement
        "WITH doomed AS (UPDATE invoices SET number = 'pwned') SELECT 1",
        "WITH doomed AS (DELETE FROM invoices) SELECT 1",
        # a UNION branch with no tenant predicate
        "SELECT number FROM invoices WHERE tenant_id = :tenant_id "
        "UNION SELECT number FROM invoices",
        # an unscoped delete
        "DELETE FROM invoices WHERE number = 'x'",
        # an unscoped select
        "SELECT number FROM invoices",
    ),
)
async def test_a_dangerous_shape_is_refused_through_the_session(
    session_factory, sql: str
) -> None:
    async with await _session(session_factory) as session:
        with pytest.raises(UnscopedRawSql):
            await session.raw_sql(sa.text(sql), {"tenant_id": TENANT_A})


async def test_a_write_hidden_in_a_cte_does_not_execute(session_factory) -> None:
    # The refusal must also mean nothing happened: if the CTE's UPDATE had run,
    # rows would carry the marker value.
    async with await _session(session_factory) as session:
        with pytest.raises(UnscopedRawSql):
            await session.raw_sql(
                sa.text("WITH doomed AS (UPDATE invoices SET number = 'pwned') SELECT 1"),
                {"tenant_id": TENANT_A},
            )
    raw = session_factory()
    await raw.execute(sa.text('SET search_path TO "jt_test"'))
    try:
        rewritten = int(
            (
                await raw.execute(
                    sa.text("SELECT count(*) FROM invoices WHERE number = 'pwned'")
                )
            ).scalar_one()
        )
    finally:
        await raw.close()
    assert rewritten == 0, "the refused statement must not have executed"
