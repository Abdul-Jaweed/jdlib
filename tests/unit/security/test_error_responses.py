"""Phase 5: security error responses (directive §20).

What is under test:

* every security failure maps to a stable code and the HTTP status the directive
  lists (401/403/404/409/423/500/503), and the envelope always carries the
  request and correlation identifiers,
* a 401 carries an RFC 6750 ``WWW-Authenticate`` challenge and nothing else
  does,
* client-visible messages are sanitized (printable, length-capped) while
  server-side failures never echo their own text — so an internal message
  containing key material cannot reach a client,
* an unclassified exception is reported as a generic 500: no exception type
  names, module paths or tracebacks ever leave the process,
* an authorization decision that could not be taken (engine unavailable) is a
  denial with **503** semantics — still never an allow, but distinguishable from
  "you may not" for clients and operators.
"""

from __future__ import annotations

import json

import pytest

from jdlib.errors import (
    CrossTenantReferenceError,
    InvalidToken,
    JdlibError,
    PermissionDenied,
    TenantAccessDenied,
    TenantSuspended,
)
from jdlib.security import errors as security_errors
from jdlib.security.authz.decision import AuthorizationDecision
from jdlib.security.authz.pep import AuthorizationPEP
from jdlib.security.context import RequestIds
from jdlib.security.errors import (
    AuthorizationUnavailable,
    SecurityConfigurationError,
    describe_error,
)
from jdlib.security.responses import error_response

SECRET_MATERIAL = "signing-key-material-that-must-never-leak"
IDS = RequestIds(request_id="req-1", correlation_id="corr-1", trace_id="trace-1")
ENVELOPE_KEYS = {"code", "message", "request_id", "correlation_id"}
ALLOWED_STATUSES = {401, 403, 404, 409, 423, 500, 503}


def _payload(exc: BaseException) -> dict[str, str]:
    return dict(error_response(exc, request_ids=IDS).payload)


# --- the seven mappings the directive lists ----------------------------------


@pytest.mark.parametrize(
    ("exc", "status"),
    [
        (InvalidToken("token rejected"), 401),
        (PermissionDenied("not allowed"), 403),
        (TenantAccessDenied("tenant not reachable"), 404),
        (CrossTenantReferenceError("doc-1", "acme", "other"), 409),
        (TenantSuspended("tenant suspended"), 423),
        (SecurityConfigurationError("bad configuration"), 500),
        (AuthorizationUnavailable("engine unavailable"), 503),
    ],
)
def test_status_mappings(exc: JdlibError, status: int) -> None:
    response = error_response(exc, request_ids=IDS)
    assert response.status == status
    assert set(response.payload) == ENVELOPE_KEYS
    assert response.payload["request_id"] == "req-1"
    assert response.payload["correlation_id"] == "corr-1"


# Errors whose constructors take more than a message.
_REQUIRED_ARGS: dict[str, dict[str, object]] = {
    "TenantNotFound": {"tenant": "acme"},
    "CrossTenantReferenceError": {
        "reference": "doc-1",
        "expected_tenant": "acme",
        "actual_tenant": "other",
    },
    "SchemaLintError": {"issues": ["missing tenant_id"]},
}


def _instance(klass: type[BaseException]) -> BaseException:
    kwargs = _REQUIRED_ARGS.get(klass.__name__)
    if kwargs is not None:
        return klass(**kwargs)  # type: ignore[call-arg]
    return klass("failure")


def test_every_mapped_error_has_an_allowed_status_and_a_full_envelope() -> None:
    # every error the security layer knows about must produce a valid envelope
    for klass, descriptor in security_errors._DESCRIPTORS.items():  # noqa: SLF001 - matrix test
        instance = _instance(klass)
        response = error_response(instance, request_ids=IDS)
        assert response.status == descriptor.http_status
        assert response.status in ALLOWED_STATUSES, klass.__name__
        assert set(response.payload) == ENVELOPE_KEYS, klass.__name__
        assert response.payload["code"] == descriptor.code.value, klass.__name__
        assert response.payload["message"], klass.__name__


# --- challenges --------------------------------------------------------------


def test_only_401_carries_a_www_authenticate_challenge() -> None:
    challenge = error_response(InvalidToken("nope"), request_ids=IDS).headers
    assert challenge["WWW-Authenticate"].startswith("Bearer")
    for exc in (
        PermissionDenied("no"),
        TenantAccessDenied("no"),
        CrossTenantReferenceError("doc-1", "acme", "other"),
        TenantSuspended("no"),
        SecurityConfigurationError("no"),
        AuthorizationUnavailable("no"),
    ):
        assert "WWW-Authenticate" not in error_response(exc, request_ids=IDS).headers


# --- leakage -----------------------------------------------------------------


@pytest.mark.parametrize(
    "exc",
    [
        InvalidToken("token rejected"),
        PermissionDenied("not allowed"),
        TenantAccessDenied("no"),
        CrossTenantReferenceError("doc-1", "acme", "other"),
        TenantSuspended("no"),
        SecurityConfigurationError(f"invalid key: {SECRET_MATERIAL}"),
        RuntimeError(f"boom {SECRET_MATERIAL}"),
        KeyError("internal-lookup-key"),
    ],
)
def test_responses_never_leak_internals(exc: BaseException) -> None:
    rendered = json.dumps(_payload(exc))
    assert SECRET_MATERIAL not in rendered
    for forbidden in ("Traceback", "File \"", "/src/", "jdlib.", "site-packages"):
        assert forbidden not in rendered


def test_server_side_failures_never_echo_their_own_message() -> None:
    payload = _payload(SecurityConfigurationError(f"invalid key: {SECRET_MATERIAL}"))
    assert SECRET_MATERIAL not in payload["message"]
    unavailable = _payload(AuthorizationUnavailable(f"cerbos at 127.0.0.1: {SECRET_MATERIAL}"))
    assert SECRET_MATERIAL not in unavailable["message"]
    assert "unavailable" in unavailable["message"].lower()


def test_unclassified_exceptions_become_a_generic_500() -> None:
    response = error_response(RuntimeError("kdjf-49f-internal"), request_ids=IDS)
    assert response.status == 500
    assert response.payload["code"] == "INTERNAL_ERROR"
    assert "RuntimeError" not in response.payload["message"]
    assert "kdjf-49f-internal" not in response.payload["message"]


def test_client_messages_are_sanitized_and_capped() -> None:
    noisy = InvalidToken("bad\x00value\x07with\x1bcontrol" + "x" * 500)
    message = _payload(noisy)["message"]
    assert "\x00" not in message and "\x07" not in message and "\x1b" not in message
    assert len(message) <= 300


def test_identifiers_are_always_present() -> None:
    ids = RequestIds(request_id="req-9")
    payload = dict(error_response(PermissionDenied("no"), request_ids=ids).payload)
    assert payload["request_id"] == "req-9"
    assert payload["correlation_id"] == "req-9"  # correlation falls back to request id


def test_descriptor_and_response_agree() -> None:
    for exc in (InvalidToken("x"), PermissionDenied("x"), AuthorizationUnavailable("x")):
        assert error_response(exc, request_ids=IDS).status == describe_error(exc).http_status


# --- the 503 path from Phase 3 -----------------------------------------------


class _DegradedPDP:
    async def decide(self, query: object) -> AuthorizationDecision:
        from datetime import UTC, datetime

        return AuthorizationDecision.unavailable(
            reason="engine_unavailable", decided_at=datetime(2026, 6, 1, tzinfo=UTC)
        )


async def test_a_degraded_engine_is_a_503_denial_not_a_403() -> None:
    from jdlib.security.authz.decision import AuthorizationQuery

    query = AuthorizationQuery(
        principal_id="user-1",
        tenant_id=__import__("uuid").UUID("11111111-2222-3333-4444-555555555555"),
        resource_kind="document",
        resource_id="doc-42",
        actions=("read",),
    )
    pep = AuthorizationPEP(pdp=_DegradedPDP())
    with pytest.raises(AuthorizationUnavailable) as excinfo:
        await pep.require(query)
    # still a denial (never an allow), but retryable and distinguishable
    assert describe_error(excinfo.value).http_status == 503
    assert describe_error(excinfo.value).retryable is True
    assert error_response(excinfo.value, request_ids=IDS).status == 503
