"""Safe error responses (directive §20, spec #21, #75).

One place turns a failure into what a client is allowed to see:

.. code-block:: json

    {"code": "PERMISSION_DENIED", "message": "...",
     "request_id": "...", "correlation_id": "..."}

Rules, each asserted by ``tests/unit/security/test_error_responses.py``:

* the envelope has exactly those four keys — no exception type names, module
  paths, tracebacks or internal identifiers,
* a 401 carries the RFC 6750 ``WWW-Authenticate`` challenge; nothing else does,
* client-visible (4xx) messages are the error's own text, made printable and
  capped at :data:`MAX_MESSAGE_LENGTH`,
* server-side (5xx) failures never echo their own text: an internal message can
  legitimately name key material or an internal endpoint, so it stays in the
  logs and the client gets a generic description,
* an unclassified exception is a generic 500 — the failure is not swallowed, it
  is simply not described to the caller.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from jdlib.security.context import RequestIds
from jdlib.security.errors import (
    SecurityClassification,
    SecurityCode,
    SecurityDescriptor,
    describe_error,
    www_authenticate,
)
from jdlib.security.redaction import REDACTED as _REDACTED
from jdlib.security.redaction import SECRET_PATTERNS as _SECRET_PATTERNS

MAX_MESSAGE_LENGTH = 300

_GENERIC_MESSAGES: dict[SecurityClassification, str] = {
    SecurityClassification.AVAILABILITY: "the service is temporarily unavailable",
    SecurityClassification.INTERNAL: "an internal error occurred",
    SecurityClassification.CONFIGURATION: "the service is misconfigured",
    SecurityClassification.AUTHORIZATION: "authorization is temporarily unavailable",
    SecurityClassification.AUTHENTICATION: "authentication could not be completed",
    SecurityClassification.TENANCY: "the tenant operation could not be completed",
    SecurityClassification.DATA_BOUNDARY: "the operation could not be completed",
}


@dataclass(frozen=True, slots=True)
class ErrorResponse:
    """A status, a safe payload and response headers."""

    status: int
    payload: Mapping[str, str]
    headers: Mapping[str, str]

    def as_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "payload": dict(self.payload),
            "headers": dict(self.headers),
        }


def _redact(message: str) -> str:
    for pattern in _SECRET_PATTERNS:
        message = pattern.sub(_REDACTED, message)
    return message


def _sanitize(message: str) -> str:
    printable = "".join(char for char in message if char.isprintable())
    collapsed = " ".join(printable.split())
    return collapsed[:MAX_MESSAGE_LENGTH]


#: The two descriptors the HTTP edges supply for failures the *core* table deliberately does
#: not know about. `jdlib.data` imports `jdlib.security` (context, audit, tracing), so the core
#: table cannot name a connector error without a cycle - the edges map those here, with the
#: same descriptor shape, so there is still exactly one envelope and one vocabulary.
VALIDATION_FAILED_DESCRIPTOR = SecurityDescriptor(
    code=SecurityCode.VALIDATION_FAILED,
    http_status=422,
    retryable=False,
    classification=SecurityClassification.VALIDATION,
)
DEPENDENCY_UNAVAILABLE_DESCRIPTOR = SecurityDescriptor(
    code=SecurityCode.DEPENDENCY_UNAVAILABLE,
    http_status=503,
    retryable=True,
    classification=SecurityClassification.AVAILABILITY,
)


def validation_failed_response(
    *, request_ids: RequestIds, message: str | None = None
) -> ErrorResponse:
    """A malformed request, in the canonical shape. Its text is sanitized like any other."""
    descriptor = VALIDATION_FAILED_DESCRIPTOR
    return ErrorResponse(
        status=descriptor.http_status,
        payload={
            "code": descriptor.code.value,
            "message": _sanitize(_redact(message)) if message else "the request failed validation",
            "request_id": request_ids.request_id,
            "correlation_id": request_ids.correlation_id or request_ids.request_id,
        },
        headers={},
    )


def error_response(
    exc: BaseException,
    *,
    request_ids: RequestIds,
    descriptor: SecurityDescriptor | None = None,
) -> ErrorResponse:
    """Build the client-visible response for a failure.

    ``descriptor`` overrides the classification the core table would give the exception. The
    HTTP edges use it for the capabilities that sit *above* this module (a connector outage, a
    spent retry budget), which the core cannot name without inverting the dependency.
    """
    descriptor = descriptor if descriptor is not None else describe_error(exc)
    if descriptor.http_status >= 500:
        message = _GENERIC_MESSAGES.get(
            descriptor.classification, _GENERIC_MESSAGES[SecurityClassification.INTERNAL]
        )
    else:
        message = _sanitize(_redact(str(exc))) or descriptor.code.value
    headers: dict[str, str] = {}
    challenge = www_authenticate(exc)
    if challenge is not None:
        headers["WWW-Authenticate"] = challenge
    return ErrorResponse(
        status=descriptor.http_status,
        payload={
            "code": descriptor.code.value,
            "message": message,
            "request_id": request_ids.request_id,
            "correlation_id": request_ids.correlation_id or request_ids.request_id,
        },
        headers=headers,
    )


__all__ = [
    "DEPENDENCY_UNAVAILABLE_DESCRIPTOR",
    "MAX_MESSAGE_LENGTH",
    "VALIDATION_FAILED_DESCRIPTOR",
    "ErrorResponse",
    "error_response",
    "validation_failed_response",
]
