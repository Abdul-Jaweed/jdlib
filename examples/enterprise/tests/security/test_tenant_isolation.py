"""Tenant isolation, measured over both surfaces and at the data.

The claim a deployment makes is not "the route checks the tenant" -- it is that a caller in one
tenant cannot reach another tenant's data **by any path**. So each question below is asked twice,
once over HTTP and once through a tool call, with credentials that really are in the control plane
and rows that really are in PostgreSQL. Both callers hold the *same* role: with the role held
constant, every difference is a difference the tenant made.

The third measurement is the data's own: a read as the owner, which does not go through the
application at all. The application's reads are evidence of what a caller can *see*; this one is
evidence of what *is*. A suite that only had the first could pass while the second was false.
"""

from __future__ import annotations

import asyncio
import uuid

import pytest

from examples.enterprise.tests.support.chain import application, http_call
from examples.enterprise.tests.support.environment import requires_cerbos
from examples.enterprise.tests.support.lab import Caller, Chain, row_status

pytestmark = requires_cerbos


def _new_resource(caller: Caller, *, name: str) -> uuid.UUID:
    """Create a resource through the API as `caller` and return its id."""
    response = http_call(caller, "POST", "/api/resources", json={"name": name, "kind": "dataset"})
    assert response.status_code == 201, response.text
    return uuid.UUID(response.json()["id"])


def test_a_resource_is_invisible_to_another_tenant(chain: Chain) -> None:
    """Alpha's row is alpha's: beta's read is answered as "no such resource", alpha's with the row.

    The status is the library's, not this example's choice: the session is bound to one tenant, so
    the row is *unreachable* to beta rather than refused, and `InvalidReference` is what the
    canonical envelope maps that to. The example's routes deliberately do not re-map it -- a second
    mapping is how an application grows a second error contract -- so what this asserts is the
    library's answer, and the assertion that matters is the message: it says the resource does not
    exist *in this tenant*, and nothing about whether it exists elsewhere.
    """
    mine = _new_resource(chain.alpha, name=f"iso-{uuid.uuid4().hex[:6]}")

    theirs = http_call(chain.beta, "GET", f"/api/resources/{mine}")
    assert theirs.status_code == 409, theirs.text
    body = theirs.json()
    assert body["code"] == "INVALID_REFERENCE"
    assert "in this tenant" in body["message"]
    assert str(chain.alpha.tenant_id) not in body["message"]

    own = http_call(chain.alpha, "GET", f"/api/resources/{mine}")
    assert own.status_code == 200, own.text
    assert own.json()["id"] == str(mine)


def test_a_listing_never_crosses_the_tenant(chain: Chain) -> None:
    """The list route returns the caller's rows -- not "the rows, filtered somewhere later"."""
    alphas = {
        _new_resource(chain.alpha, name=f"list-a-{uuid.uuid4().hex[:6]}") for _ in range(2)
    }
    betas = {_new_resource(chain.beta, name=f"list-b-{uuid.uuid4().hex[:6]}") for _ in range(2)}

    page = http_call(chain.alpha, "GET", "/api/resources?limit=200")
    assert page.status_code == 200, page.text
    returned = {uuid.UUID(row["id"]) for row in page.json()["resources"]}

    assert alphas <= returned
    assert returned.isdisjoint(betas)

    # And the data itself: every row exists, in one tenant or the other. Invisibility is the
    # caller's, not the database's -- a suite that only checked the listing could not tell the
    # difference between "beta's rows are hidden" and "beta's rows were never written".
    for resource_id in betas:
        assert row_status(resource_id) == "active"


def test_both_surfaces_answer_the_same_question_the_same_way(chain: Chain) -> None:
    """HTTP and MCP over the same credential: the tool sees exactly what the route sees."""
    mine = _new_resource(chain.alpha, name=f"both-{uuid.uuid4().hex[:6]}")

    async def _body() -> tuple[str | None, int, int]:
        async with application() as live:
            theirs = await live.tool(chain.beta, "resource_get", {"resource_id": str(mine)})
            beta_http = await live.http(chain.beta, "GET", f"/api/resources/{mine}")
            alpha_http = await live.http(chain.alpha, "GET", f"/api/resources/{mine}")
            return theirs.data, beta_http.status_code, alpha_http.status_code

    tool_data, beta_status, alpha_status = asyncio.run(_body())

    assert tool_data is None, "the tool reached another tenant's row"
    assert beta_status == 409, "the route answered something other than the library's mapping"
    assert alpha_status == 200


def test_an_identity_claim_in_the_request_is_ignored(chain: Chain) -> None:
    """A header naming another tenant changes nothing: the tenant comes from the credential.

    This is the shape an attacker reaches for first, so it is asserted against the *answer*: alpha's
    own tenant is what the route reports, and beta's rows stay out of alpha's listing while the
    header claims to be beta.
    """
    betas = {_new_resource(chain.beta, name=f"claim-b-{uuid.uuid4().hex[:6]}")}

    response = http_call(
        chain.alpha,
        "GET",
        "/api/whoami",
        headers={"x-tenant-id": str(chain.beta.tenant_id), "x-tenant": "beta"},
    )
    assert response.status_code == 200, response.text
    assert response.json()["tenant"] == chain.alpha.tenant_slug

    page = http_call(
        chain.alpha,
        "GET",
        "/api/resources?limit=200",
        headers={"x-tenant-id": str(chain.beta.tenant_id)},
    )
    returned = {uuid.UUID(row["id"]) for row in page.json()["resources"]}
    assert returned.isdisjoint(betas)


def test_a_forged_key_is_refused_by_both_surfaces(chain: Chain) -> None:
    """The negative control: a key the control plane has never seen gets nowhere, on either surface.

    Without this, every assertion above would also hold for a boundary that authenticated nobody.
    """
    from fastmcp.exceptions import ToolError

    forged = chain.alpha.forged()
    mine = _new_resource(chain.alpha, name=f"forged-{uuid.uuid4().hex[:6]}")

    refused = http_call(forged, "GET", f"/api/resources/{mine}")
    assert refused.status_code == 401, refused.text

    async def _body() -> None:
        async with application() as live:
            with pytest.raises(ToolError, match="no credentials presented"):
                await live.tool(forged, "resource_get", {"resource_id": str(mine)})

    asyncio.run(_body())


def test_a_caller_with_no_credential_is_refused_before_any_tenant_exists(chain: Chain) -> None:
    """No token at all: 401 from the middleware, and the envelope -- not a 500 from deeper in."""
    response = http_call(None, "GET", "/api/whoami")
    assert response.status_code == 401, response.text
    # The canonical envelope, exactly: four keys, and none of them internal.
    assert set(response.json()) == {"code", "message", "request_id", "correlation_id"}
    assert response.headers["www-authenticate"].startswith("Bearer")
