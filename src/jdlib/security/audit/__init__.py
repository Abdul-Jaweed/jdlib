"""Security audit surface.

Deliberate public API of the audit layer: the event vocabulary, the envelope and
(added alongside) the recorder, exporter and integrity helpers. Importing this
namespace pulls no optional dependency.
"""

from jdlib.security.audit.access import AuditAccess, AuditCapability
from jdlib.security.audit.adapters import AuditPrivilegeAudit, AuditRawSqlAuditor
from jdlib.security.audit.emitters import (
    DecisionObserver,
    NullSecurityEventSink,
    SecurityEventSink,
    TransactionAuditSink,
    authorization_audit_event,
    authorization_audit_observer,
)
from jdlib.security.audit.events import (
    AuditOutcome,
    AuditSource,
    SecurityAuditEvent,
    SecurityEventType,
    audit_metadata,
)
from jdlib.security.audit.export import (
    DEFAULT_EXPORT_LIMIT,
    MAX_EXPORT_LIMIT,
    AuditPage,
    AuditQuery,
    export_events,
    iter_records,
    read_events,
    render_csv,
    render_json,
    render_jsonl,
)

__all__ = [
    "DEFAULT_EXPORT_LIMIT",
    "MAX_EXPORT_LIMIT",
    "AuditAccess",
    "AuditPrivilegeAudit",
    "AuditRawSqlAuditor",
    "AuditCapability",
    "AuditOutcome",
    "AuditPage",
    "AuditQuery",
    "AuditSource",
    "DecisionObserver",
    "NullSecurityEventSink",
    "SecurityAuditEvent",
    "SecurityEventSink",
    "SecurityEventType",
    "TransactionAuditSink",
    "audit_metadata",
    "authorization_audit_event",
    "authorization_audit_observer",
    "export_events",
    "iter_records",
    "read_events",
    "render_csv",
    "render_json",
    "render_jsonl",
]
