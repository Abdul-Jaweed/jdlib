"""Security audit surface.

Deliberate public API of the audit layer: the event vocabulary, the envelope and
(added alongside) the recorder, exporter and integrity helpers. Importing this
namespace pulls no optional dependency.
"""

from jdlib.security.audit.events import (
    AuditOutcome,
    AuditSource,
    SecurityAuditEvent,
    SecurityEventType,
    audit_metadata,
)

__all__ = [
    "AuditOutcome",
    "AuditSource",
    "SecurityAuditEvent",
    "SecurityEventType",
    "audit_metadata",
]
