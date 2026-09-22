import uuid

import pytest

from jdlib.control.audit import NullPlatformAudit, PlatformAudit, RecordingPlatformAudit


class _FakeAsyncSession:
    def __init__(self) -> None:
        self.committed = False
        self.rolled_back = False
        self.closed = False

    async def commit(self) -> None:
        self.committed = True

    async def rollback(self) -> None:
        self.rolled_back = True

    async def close(self) -> None:
        self.closed = True


async def test_recording_audit_records_entries():
    audit = RecordingPlatformAudit()
    await audit.record(
        action="tenant.created", tenant_id=uuid.uuid4(), actor_id=None, metadata={"slug": "acme"}
    )
    assert audit.entries[0]["action"] == "tenant.created"
    assert audit.entries[0]["metadata"] == {"slug": "acme"}


async def test_null_audit_fails_closed():
    audit = NullPlatformAudit()
    with pytest.raises(RuntimeError):
        await audit.record(action="tenant.created", tenant_id=None, actor_id=None, metadata=None)


def test_protocol_shape():
    assert hasattr(PlatformAudit, "record")
