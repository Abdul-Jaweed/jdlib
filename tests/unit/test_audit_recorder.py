import uuid

from jdlib.context import Principal, PrincipalKind, TenantContext, context_scope
from jdlib.control.enums import ActorType, PlacementStrategy
from jdlib.errors import MissingTenantContext
from jdlib.models.audit_recorder import TenantAuditRecorder


class _Session:
    def __init__(self) -> None:
        self.added: list[object] = []

    def add(self, obj: object) -> None:
        self.added.append(obj)


def _context() -> TenantContext:
    return TenantContext(
        tenant_id=uuid.uuid4(),
        tenant_slug="acme",
        strategy=PlacementStrategy.SHARED,
        principal=Principal(kind=PrincipalKind.USER, id=uuid.uuid4()),
        request_id="req",
        correlation_id="corr",
        trace_id="trace",
    )


def test_recorder_requires_context():
    recorder = TenantAuditRecorder(_Session())  # type: ignore[arg-type]
    try:
        recorder.record(action="invoice.updated")
    except MissingTenantContext:
        pass
    else:
        raise AssertionError("expected MissingTenantContext")


def test_recorder_stamps_context_fields():
    session = _Session()
    recorder = TenantAuditRecorder(session)  # type: ignore[arg-type]
    with context_scope(_context()):
        record = recorder.record(
            action="invoice.updated", target_type="invoice", target_id=uuid.uuid4(),
            metadata={"status": "paid"},
        )
    assert record.action == "invoice.updated"
    assert record.actor_type == ActorType.USER.value
    assert record.request_id == "req"
    assert record.correlation_id == "corr"
    assert record.trace_id == "trace"
    assert record in session.added
