import base64
import json
import uuid
from datetime import datetime, timedelta

import pytest

from jdlib.config import ContextConfig
from jdlib.context import EnvelopeCodec, Principal, PrincipalKind, TenantContext
from jdlib.control.enums import PlacementStrategy
from jdlib.errors import ExpiredToken, InvalidToken
from tests.support.context_fakes import FrozenClock

TENANT_ID = uuid.UUID("00000000-0000-0000-0000-0000000000aa")


def _context() -> TenantContext:
    return TenantContext(
        tenant_id=TENANT_ID,
        tenant_slug="acme",
        strategy=PlacementStrategy.SHARED,
        principal=Principal(kind=PrincipalKind.USER, id=uuid.uuid4(), scopes=frozenset({"x"})),
        request_id="req-1",
        correlation_id="corr-1",
        trace_id="trace-1",
    )


def _codec(clock: FrozenClock | None = None) -> EnvelopeCodec:
    return EnvelopeCodec(
        config=ContextConfig(signing_key="sign-key"), clock=clock or FrozenClock()
    )


def test_roundtrip_preserves_identity_fields_only():
    codec = _codec()
    envelope = codec.decode(codec.encode(_context()))
    assert envelope.tenant_id == TENANT_ID
    assert envelope.principal_type is PrincipalKind.USER
    assert envelope.request_id == "req-1"
    assert envelope.correlation_id == "corr-1"
    assert envelope.trace_id == "trace-1"
    assert not hasattr(envelope, "scopes")


def test_token_does_not_contain_permissions_or_scopes():
    token = _codec().encode(_context())
    payload_b64 = token.split(".")[0]
    payload = json.loads(base64.urlsafe_b64decode(payload_b64 + "=" * (-len(payload_b64) % 4)))
    assert "scopes" not in payload
    assert "permissions" not in payload


def test_tampered_payload_rejected():
    codec = _codec()
    payload, signature = codec.encode(_context()).split(".")
    forged = base64.urlsafe_b64encode(
        json.dumps({"tenant_id": str(TENANT_ID)}).encode()
    ).rstrip(b"=").decode()
    with pytest.raises(InvalidToken):
        codec.decode(f"{forged}.{signature}")


def test_tampered_signature_rejected():
    codec = _codec()
    payload, _ = codec.encode(_context()).split(".")
    with pytest.raises(InvalidToken):
        codec.decode(f"{payload}.AAAA")


def test_expired_envelope_rejected():
    clock = FrozenClock()
    codec = _codec(clock)
    token = codec.encode(_context())
    clock.advance(timedelta(minutes=6))
    with pytest.raises(ExpiredToken):
        codec.decode(token)


def test_future_envelope_rejected():
    clock = FrozenClock()
    codec = _codec(clock)
    token = codec.encode(_context())
    clock.advance(timedelta(minutes=-5))
    with pytest.raises(InvalidToken):
        codec.decode(token)


def test_malformed_token_rejected():
    with pytest.raises(InvalidToken):
        _codec().decode("not-a-token")


def test_naive_issued_at_is_invalid_token_not_type_error():
    naive_codec = EnvelopeCodec(
        config=ContextConfig(signing_key="sign-key"),
        clock=FrozenClock(now=datetime(2026, 1, 1)),
    )
    token = naive_codec.encode(_context())
    with pytest.raises(InvalidToken):
        _codec().decode(token)


def test_junk_payload_segment_rejected():
    codec = _codec()
    _, signature = codec.encode(_context()).split(".")
    with pytest.raises(InvalidToken):
        codec.decode(f"!!!.{signature}")
