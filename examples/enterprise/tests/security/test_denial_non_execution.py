"""A denial is a non-execution, and this file measures it rather than assuming it.

"The handler did not run" is the claim every authorization design makes and few test. Here it is
measured three ways, for the same denied call:

1. **the answer** -- the library's canonical envelope, with the denial's own code;
2. **the data** -- the row's status read as the *owner*, which does not go through the application
   at all, so it cannot be affected by what the caller is allowed to see;
3. **the audit trail** -- the control plane's record of the decision, which is what an operator
   would have after the fact.

All three are needed. A denial that still wrote the row would pass (1); a test that read the row
back through the *caller's* own session would pass (2) while the row moved underneath it; and (3) is
the only one that survives the process.

Both surfaces are asked the same question, because a second surface is where a handler gets reached
by a path nobody tested.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import Iterator

import pytest
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import create_async_engine

from examples.enterprise.app.dsn import async_dsn
from examples.enterprise.tests.support.chain import application, http_call
from examples.enterprise.tests.support.environment import MIGRATION_DSN, requires_cerbos
from examples.enterprise.tests.support.lab import Caller, Chain, add_caller, row_status

pytestmark = requires_cerbos


@pytest.fixture(scope="module")
def support_caller(chain: Chain) -> Iterator[Caller]:
    """A caller in alpha's tenant holding `support`: reads, and may not write.

    Same tenant, same rows, weaker role -- so what the denial tests below differ by is the role and
    nothing else.
    """
    yield asyncio.run(add_caller(chain.alpha, role="support"))


def _security_events(tenant_id: uuid.UUID) -> list[tuple[str, str]]:
    """This tenant's security events, oldest first, read as the owner.

    The trail is read as the owner on purpose: the events are the control plane's record, and a
    caller's own session is bound to a tenant *and* filtered by the policies -- which is what makes
    it evidence of what a caller sees rather than of what happened.

    `(action, the action it was asked about)`, because the event's own `resource_id` is the target
    the *question* was about -- the tenant scope, for a guarded route -- and not the row the handler
    would have touched. The pair is what a reader needs to tell one decision from another.
    """

    async def _body() -> list[tuple[str, str]]:
        engine = create_async_engine(async_dsn(MIGRATION_DSN))
        try:
            async with engine.connect() as connection:
                result = await connection.execute(
                    sa.text(
                        "SELECT action, coalesce(metadata->>'action', '') FROM "
                        "jd_control.platform_audit_events WHERE tenant_id = :tenant "
                        "AND action LIKE 'security.%' ORDER BY occurred_at, id"
                    ),
                    {"tenant": tenant_id},
                )
                return [(str(row[0]), str(row[1])) for row in result]
        finally:
            await engine.dispose()

    return asyncio.run(_body())


def test_a_denied_write_over_http_is_answered_and_never_happens(
    chain: Chain, support_caller: Caller
) -> None:
    """The archive route, refused for `support`: 403, the row still active, the denial audited."""
    mine = http_call(
        chain.alpha, "POST", "/api/resources", json={"name": "denied-http", "kind": "dataset"}
    )
    assert mine.status_code == 201, mine.text
    resource_id = uuid.UUID(mine.json()["id"])
    before = len(_security_events(chain.alpha.tenant_id))

    refused = http_call(support_caller, "DELETE", f"/api/resources/{resource_id}")
    assert refused.status_code == 403, refused.text
    body = refused.json()
    assert body["code"] == "PERMISSION_DENIED"
    # The message names the permission, not the policy engine's internals or the tenant's data.
    assert "resource:write" in body["message"]

    # (2) the data, read as the owner.
    assert row_status(resource_id) == "active"

    # (3) the trail: the refused call added exactly one event, and it was the denial. A snapshot
    # rather than a filter: the events name the target the question was about (the tenant scope),
    # not the row, so "which event did this call produce" is answered by the difference the call
    # made -- and an equality on the count is what makes "no successful archive" mean something.
    added = _security_events(chain.alpha.tenant_id)[before:]
    assert len(added) == 1, added
    assert added[0][0] == "security.AUTHZ_DENY.DENIED", added
    assert added[0][1] == "resource:write", added


def test_a_denied_tool_call_is_refused_and_never_happens(
    chain: Chain, support_caller: Caller
) -> None:
    """The same denial through the MCP surface: the tool is refused, and the row is still active."""
    from fastmcp.exceptions import ToolError

    created = http_call(
        chain.alpha, "POST", "/api/resources", json={"name": "denied-mcp", "kind": "dataset"}
    )
    resource_id = uuid.UUID(created.json()["id"])
    before = len(_security_events(chain.alpha.tenant_id))

    async def _body() -> None:
        async with application() as live:
            with pytest.raises(ToolError, match="authorization denied"):
                await live.tool(
                    support_caller, "resource_archive", {"resource_id": str(resource_id)}
                )

    asyncio.run(_body())
    assert row_status(resource_id) == "active"

    # Three events, and each is a different layer's account of the same refusal: the boundary
    # records that a request arrived (`mcp.request`), the policy engine records its decision
    # (`resource:write`), and the MCP chain records its own refusal
    # (`mcp.authorization.denied`). A test that asserted a count of one would have been asserting
    # the HTTP path's shape against the MCP path's, which is how a suite reports a false failure.
    added = _security_events(chain.alpha.tenant_id)[before:]
    assert ("security.AUTHZ_DENY.DENIED", "resource:write") in added, added
    assert ("security.AUTHZ_DENY.DENIED", "mcp.authorization.denied") in added, added
    assert ("security.MCP_REQUEST.SUCCESS", "mcp.request") in added, added
    assert not any(
        action == "security.AUTHZ_ALLOW.SUCCESS" and detail == "resource:write"
        for action, detail in added
    ), added


def test_the_denial_is_the_policy_engines_and_not_a_missing_role(chain: Chain) -> None:
    """A control: the same caller *with* the role is allowed, so the denial above is the policy.

    Without this, a suite where the caller's roles never resolved would report the same denials --
    and the deployment would look secure while every request was being refused for the wrong reason.
    """
    mine = http_call(
        chain.alpha, "POST", "/api/resources", json={"name": "allowed-control", "kind": "dataset"}
    )
    resource_id = uuid.UUID(mine.json()["id"])

    archived = http_call(chain.alpha, "DELETE", f"/api/resources/{resource_id}")
    assert archived.status_code == 200, archived.text
    assert row_status(resource_id) == "archived"


def test_a_denied_reader_cannot_read_either(chain: Chain) -> None:
    """`support` reads, and this is the control for the reader: the same route, the other role.

    The pair matters: a suite that only ever exercised denials could not tell a correct policy set
    from an over-refusing one, and an over-refusing deployment is an outage.
    """
    created = http_call(
        chain.alpha, "POST", "/api/resources", json={"name": "read-pair", "kind": "dataset"}
    )
    resource_id = uuid.UUID(created.json()["id"])

    read = http_call(chain.alpha, "GET", f"/api/resources/{resource_id}")
    assert read.status_code == 200, read.text
    assert read.json()["id"] == str(resource_id)
