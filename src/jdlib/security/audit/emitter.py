"""Where a security event goes, and the rule that it can never change an outcome.

The library ships sinks, not a policy about which emitter an application installs. A boundary
therefore takes an optional emitter, and every boundary is expected to be able to run without
one - telemetry and audit are configuration, not preconditions for serving a request.

Two properties are deliberate. An emitter that raises does not change what the caller does: a
refusal is still raised and a success still returns, because an audit outage that turns into an
outage of the operation is worse than the gap it was trying to record. And a missing emitter is
reported as *not delivered* rather than silently counted as recorded - `emit_safely` returns
whether the event actually reached the emitter, so a test can tell the two apart.
"""

from __future__ import annotations

from typing import Protocol

from jdlib.security.audit.events import SecurityAuditEvent


class SecurityEventEmitter(Protocol):
    """Anything that accepts a security event: a sink, a queue, a test recorder."""

    def __call__(self, event: SecurityAuditEvent) -> None: ...


def emit_safely(emitter: SecurityEventEmitter | None, event: SecurityAuditEvent) -> bool:
    """Deliver one event, and never let the delivery change the caller's outcome."""
    if emitter is None:
        return False
    try:
        emitter(event)
    except Exception:  # noqa: BLE001 - an audit outage is not the caller's failure
        return False
    return True
