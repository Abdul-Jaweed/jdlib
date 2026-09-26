"""What a failure is allowed to say.

The canonical envelope is a *contract*: four keys, no exception names, no module paths, no
tracebacks, no internal identifiers. The library asserts that contract on its own builders; this
file asserts it **end to end**, on the answers a real deployment gives to the requests an attacker
sends first -- because a contract that holds in a unit test and not over the wire is a contract that
holds nowhere.

Every probe is a request that fails, and every answer is checked against the same deny-list. The
list is deliberately about *internals* rather than about words: a message may name the permission
that was refused (that is the caller's business) and may name the id the caller itself supplied; it
may not name a table, a driver, a DSN, a module or a line of code.
"""

from __future__ import annotations

import asyncio
import uuid
from typing import cast

import pytest

from examples.enterprise.tests.support.chain import application, http_call
from examples.enterprise.tests.support.environment import requires_cerbos
from examples.enterprise.tests.support.lab import Caller, Chain

pytestmark = requires_cerbos

#: What no client-visible answer may contain. Each entry is something a leak would carry: a driver's
#: exception class, the schema the control plane lives in, the library's own module path, a
#: connection string, SQL, or the two shapes a stack trace always has.
FORBIDDEN = (
    "traceback",
    "sqlalchemy",
    "asyncpg",
    "psycopg",
    "jdlib",
    "jd_control",
    "postgresql://",
    "select ",
    "insert ",
    "password",
    "file \"",
    "line ",
)

ENVELOPE_KEYS = {"code", "message", "request_id", "correlation_id"}


def _assert_no_internals(response: object) -> dict[str, str]:
    """The envelope, exactly -- and nothing in it that names an internal."""
    body = cast("dict[str, str]", response.json())  # type: ignore[attr-defined]
    assert set(body) == ENVELOPE_KEYS, body
    for key, value in body.items():
        lowered = str(value).lower()
        for marker in FORBIDDEN:
            assert marker not in lowered, f"{key} leaked {marker!r}: {value!r}"
    return body


def _new_resource(caller: Caller) -> uuid.UUID:
    response = http_call(
        caller, "POST", "/api/resources", json={"name": "surface", "kind": "dataset"}
    )
    assert response.status_code == 201, response.text
    return uuid.UUID(response.json()["id"])


def test_no_credential_is_a_401_in_the_envelope(chain: Chain) -> None:
    response = http_call(None, "GET", "/api/whoami")
    assert response.status_code == 401, response.text
    _assert_no_internals(response)
    assert response.headers["www-authenticate"].startswith("Bearer")


def test_a_malformed_credential_is_the_same_answer(chain: Chain) -> None:
    """A key that is not a key: refused, and with the *same* answer as no key at all.

    The same answer is the point -- an attacker learns nothing from the difference, and neither
    does a client's retry logic.
    """
    without = http_call(None, "GET", "/api/whoami")
    malformed = http_call(
        None, "GET", "/api/whoami", headers={"authorization": "Bearer not-a-key"}
    )
    assert malformed.status_code == without.status_code == 401
    assert _assert_no_internals(malformed)["code"] == _assert_no_internals(without)["code"]


def test_an_unknown_route_is_answered_in_the_envelope(chain: Chain) -> None:
    """Under the mount and outside it: a 404 is still the documented shape."""
    inside = http_call(chain.alpha, "GET", "/api/nothing-here")
    assert inside.status_code == 404, inside.text
    _assert_no_internals(inside)

    outside = http_call(chain.alpha, "GET", "/nothing-here")
    assert outside.status_code == 404, outside.text
    _assert_no_internals(outside)


def test_a_malformed_body_is_a_validation_failure_not_a_traceback(chain: Chain) -> None:
    """The request validator's answer goes through the envelope too, with its own code."""
    response = http_call(
        chain.alpha, "POST", "/api/resources", json={"name": 123, "kind": "dataset"}
    )
    assert response.status_code == 422, response.text
    body = _assert_no_internals(response)
    assert body["code"] == "VALIDATION_FAILED"


def test_an_unreachable_row_says_so_without_saying_where_it_is(chain: Chain) -> None:
    """A resource that is not in this tenant: the message names the caller's own id, and no more."""
    absent = http_call(chain.alpha, "GET", f"/api/resources/{uuid.uuid4()}")
    assert absent.status_code == 409, absent.text
    body = _assert_no_internals(absent)
    assert body["code"] == "INVALID_REFERENCE"

    theirs = _new_resource(chain.beta)
    crossed = http_call(chain.alpha, "GET", f"/api/resources/{theirs}")
    assert crossed.status_code == 409, crossed.text
    crossed_body = _assert_no_internals(crossed)
    # The caller's own supplied id is echoed -- that is theirs -- and nothing else about the row.
    assert str(theirs) in crossed_body["message"]
    assert str(chain.beta.tenant_id) not in crossed_body["message"]


def test_a_tool_call_failure_carries_no_internals_either(chain: Chain) -> None:
    """The MCP surface's refusals, probe by probe -- and the two kinds of refusal differ.

    A **schema** refusal is answered precisely, because the library decided it and knows what is
    safe to say ("does not declare", "missing required arguments"). A failure *inside* the handler
    is answered generically ("the tool could not complete"), because the library cannot know which
    part of a driver's exception is safe to repeat -- and a malformed uuid reaching the service is
    exactly that case. Both are the contract; asserting one shape for both would have been asserting
    the wrong thing twice.
    """
    from fastmcp.exceptions import ToolError

    probes: tuple[tuple[dict[str, object], str], ...] = (
        ({"resource_id": "not-a-uuid"}, "could not complete"),
        ({"resource_id": str(uuid.uuid4()), "extra": "unexpected"}, "does not declare: extra"),
        ({}, "missing required arguments: resource_id"),
    )

    async def _body() -> list[tuple[str, str]]:
        answers: list[tuple[str, str]] = []
        async with application() as live:
            for arguments, _expected in probes:
                with pytest.raises(ToolError) as caught:
                    await live.tool(chain.alpha, "resource_get", arguments)
                answers.append((repr(arguments), str(caught.value)))
        return answers

    for (arguments, expected), (_echoed, message) in zip(probes, asyncio.run(_body()), strict=True):
        assert expected in message, f"{arguments!r} -> {message!r}"
        lowered = message.lower()
        for marker in FORBIDDEN:
            assert marker not in lowered, f"the tool surface leaked {marker!r}: {message!r}"
        # A uuid parse failure is the interesting one: its own exception text names the type.
        assert "uuid" not in lowered, message
