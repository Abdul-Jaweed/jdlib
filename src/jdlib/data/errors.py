from __future__ import annotations

from jdlib.errors import JdlibError


class ConnectorError(JdlibError):
    """A connector operation failed.

    ``transient`` says whether the failure is worth another attempt. The policy consults the
    library's own is_retryable() first and falls back to this flag, so an error the taxonomy
    already understands - a DBAPI connection reset, say - is classified once and not twice.
    """

    def __init__(self, *args: object, transient: bool = False) -> None:
        super().__init__(*args)
        self.transient = transient


class ConnectorTimeoutError(ConnectorError):
    """An operation exceeded the policy's timeout."""


class CircuitOpenError(ConnectorError):
    """The circuit is open: repeated failures, so calls are refused without being attempted."""


class AuthorizationRefusedError(ConnectorError):
    """A connector could not verify it was given an authorized context, and refused to open.

    Fail closed. A connector that opens on an unverified context is how a resource gets used
    by the wrong tenant, and no amount of downstream checking repairs that.
    """
