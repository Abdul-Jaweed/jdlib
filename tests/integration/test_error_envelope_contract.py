"""The canonical error envelope, asserted where a client would see it.

`docs/security/error-responses.md` and `jdlib.security.responses` define one shape -
`{"code","message","request_id","correlation_id"}`, with `WWW-Authenticate` on a 401 - and
until now two HTTP edges answered with something else: the tenant middleware and the FastAPI
integration both sent `{"error": <class name>, "detail": <the exception's text>}`, for every
status. That is the defect this module pins.

The one that matters most is the 5xx case. The old shape echoed `str(exc)` to the client
whatever the status was, and a server-side failure message can legitimately name a DSN, an
internal endpoint or key material - `docs/security/error-responses.md` says so in as many
words. A 4xx still carries its own (printable, redacted, capped) text, because that text is
written for a caller; a 5xx never does.
"""

from __future__ import annotations

import fastapi
import httpx
import pytest
import sqlalchemy as sa
from fastapi.exceptions import HTTPException  # noqa: F401  (documented edge case below)

from jdlib.data.errors import ConnectorError, ConnectorTimeoutError
from jdlib.errors import ProvisioningError, TenantAccessDenied
from jdlib.integrations.fastapi import install_error_envelope
from jdlib.reliability import RetryBudgetExhaustedError

CANONICAL_KEYS = {"code", "message", "request_id", "correlation_id"}

#: A 5xx message of exactly the kind that must never reach a client: a DSN with a password in
#: it. The OTel harness records the same string for the same reason.
SECRET_BEARING_MESSAGE = "postgresql+asyncpg://app:s3cr3t-pw@db.internal:5432/jdlib"


def _api(raise_on: Exception) -> fastapi.FastAPI:
    api = fastapi.FastAPI()
    install_error_envelope(api)

    @api.get("/boom")
    async def boom() -> None:
        raise raise_on

    @api.post("/needs-a-body")
    async def needs_a_body(payload: dict[str, str]) -> dict[str, str]:
        return payload

    return api


async def _get(error: Exception, path: str = "/boom") -> httpx.Response:
    transport = httpx.ASGITransport(app=_api(error), raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://jdlib.test") as client:
        return await client.get(path)


async def _post_json(body: object) -> httpx.Response:
    api = fastapi.FastAPI()
    install_error_envelope(api)

    @api.post("/needs-a-body")
    async def needs_a_body(payload: dict[str, str]) -> dict[str, str]:
        return payload

    transport = httpx.ASGITransport(app=api, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://jdlib.test") as client:
        return await client.post("/needs-a-body", json=body)


@pytest.mark.asyncio
async def test_a_5xx_never_echoes_its_own_message() -> None:
    """The regression the directive names: the old handler sent `str(exc)` on every status."""
    response = await _get(ProvisioningError(SECRET_BEARING_MESSAGE))

    assert response.status_code == 500
    body = response.json()
    assert set(body) == CANONICAL_KEYS
    assert body["code"] == "PROVISIONING_ERROR"
    assert body["message"] == "an internal error occurred"
    assert "s3cr3t-pw" not in response.text
    assert "db.internal" not in response.text


@pytest.mark.asyncio
async def test_a_4xx_keeps_the_caller_facing_text() -> None:
    """A message written for a caller is the caller's to read; the rules differ by status."""
    response = await _get(TenantAccessDenied("the caller has no roles in this tenant"))

    assert response.status_code == 404
    body = response.json()
    assert set(body) == CANONICAL_KEYS
    assert body["code"] == "TENANT_ACCESS_DENIED"
    assert body["message"] == "the caller has no roles in this tenant"


@pytest.mark.asyncio
async def test_an_unexpected_exception_is_a_generic_500() -> None:
    response = await _get(RuntimeError("an implementation detail with postgres://user:pw@host"))

    assert response.status_code == 500
    body = response.json()
    assert set(body) == CANONICAL_KEYS
    assert body["code"] == "INTERNAL_ERROR"
    assert body["message"] == "an internal error occurred"
    assert "postgres://user:pw@host" not in response.text
    assert "RuntimeError" not in response.text


@pytest.mark.asyncio
@pytest.mark.asyncio
async def test_a_connection_level_database_error_is_503_but_a_rejected_statement_is_500() -> None:
    """Selectivity is the assertion: a handler that mapped every DBAPIError would pass a
    one-sided test, and would hide the defects the 500 exists to report."""
    refused = await _get(sa.exc.OperationalError("SELECT 1", {}, Exception("connection refused")))
    assert refused.status_code == 503
    assert refused.json()["code"] == "DEPENDENCY_UNAVAILABLE"
    assert "connection refused" not in refused.text

    rejected = await _get(
        sa.exc.ProgrammingError("SELECT nope", {}, Exception("column does not exist"))
    )
    assert rejected.status_code == 500
    assert rejected.json()["code"] == "INTERNAL_ERROR"


@pytest.mark.asyncio
async def test_an_applications_own_http_exception_still_answers_the_envelope() -> None:
    """Starlette answers `HTTPException` in a shape of its own - `{"detail": ...}`, no code,
    no ids - so an application that raises one for its own rule (a duplicate name, a missing
    project) was answering a fourth shape and bypassing the contract entirely."""
    conflict = await _get(
        HTTPException(status_code=409, detail="a project already exists in this tenant")
    )
    assert conflict.status_code == 409
    body = conflict.json()
    assert set(body) == {"code", "message", "request_id", "correlation_id"}
    assert body["code"] == "CONFLICT"
    assert body["message"] == "a project already exists in this tenant"

    missing = await _get(HTTPException(status_code=404, detail="no such project"))
    assert missing.status_code == 404
    assert missing.json()["code"] == "NOT_FOUND"


@pytest.mark.asyncio
async def test_a_retry_after_header_survives_but_a_5xx_still_says_nothing() -> None:
    """A 429 that FastAPI was told to send with `Retry-After` must keep it: the client acts on
    it. And an `HTTPException` cannot be used to smuggle a 5xx message out - the generic
    description wins above 499, which is the rule this whole module exists for."""
    limited = await _get(
        HTTPException(status_code=429, detail="slow down", headers={"Retry-After": "30"})
    )
    assert limited.status_code == 429
    assert limited.headers["retry-after"] == "30"
    assert limited.json()["code"] == "TOO_MANY_REQUESTS"

    server = await _get(HTTPException(status_code=500, detail="dsn=postgresql://u:p@h/db"))
    assert server.status_code == 500
    assert server.json()["message"] == "an internal error occurred"
    assert "dsn=" not in server.text


@pytest.mark.asyncio
async def test_the_envelope_always_carries_both_ids() -> None:
    response = await _get(TenantAccessDenied("nope"))

    body = response.json()
    assert body["request_id"]
    assert body["correlation_id"]
    assert body["request_id"] != body["correlation_id"]


@pytest.mark.asyncio
async def test_a_401_carries_the_rfc6750_challenge() -> None:
    from jdlib.errors import AuthenticationError

    response = await _get(AuthenticationError("no credentials presented"))

    assert response.status_code == 401
    assert response.headers["www-authenticate"].lower().startswith("bearer")
    assert response.json()["code"] == "AUTHENTICATION_REQUIRED"


@pytest.mark.asyncio
async def test_a_malformed_body_is_a_validation_failure_not_a_500() -> None:
    response = await _post_json({"expected": "a string", "but_this_is_not": 1})

    assert response.status_code == 422
    body = response.json()
    assert set(body) == CANONICAL_KEYS
    assert body["code"] == "VALIDATION_FAILED"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "error",
    [
        ConnectorError("the pool is exhausted"),
        ConnectorTimeoutError("statement timed out"),
        RetryBudgetExhaustedError("spent"),
    ],
)
async def test_dependency_failures_are_503_not_500(error: Exception) -> None:
    """An outage and a defect must not share a status: the caller's retry differs."""
    response = await _get(error)

    assert response.status_code == 503
    body = response.json()
    assert set(body) == CANONICAL_KEYS
    assert body["code"] == "DEPENDENCY_UNAVAILABLE"
    assert "the pool is exhausted" not in response.text
    assert "spent" not in response.text

@pytest.mark.asyncio
async def test_a_driver_raw_connection_failure_is_503_not_an_unhandled_500() -> None:
    """The driver's own refusal reaches the edge unwrapped -- asyncpg's does exactly that.

    SQLAlchemy wraps a failure *inside* a statement, but a pool connect the database refuses
    surfaces as the driver's own ``ConnectionRefusedError``: an ``OSError``, not a ``DBAPIError``.
    A table that lists only SQLAlchemy's wrappers therefore answers a database that is *down* with
    an unhandled 500 -- and every request path and every readiness probe depends on this row.
    """
    response = await _get(ConnectionRefusedError("connect to db.internal:5432 refused"))

    assert response.status_code == 503
    body = response.json()
    assert set(body) == CANONICAL_KEYS
    assert body["code"] == "DEPENDENCY_UNAVAILABLE"
    assert "db.internal" not in response.text
