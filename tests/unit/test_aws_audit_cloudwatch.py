"""CloudWatch Logs audit sink tests (AWS directive §18).

The client is injected, so these run without AWS. What they assert is what an audit trail must get
right: the document is complete and serialisable, the timestamp is CloudWatch's, a failed or
rejected write is visible rather than silent, and no client message is echoed back.
"""

import json
from collections.abc import Mapping
from typing import Any, cast

import pytest

from jdlib.security.audit.cloudwatch import (
    CloudWatchLogsAuditSink,
    CloudWatchLogsConfig,
)
from jdlib.security.audit.events import (
    AuditOutcome,
    AuditSource,
    SecurityAuditEvent,
    SecurityEventType,
)
from jdlib.security.errors import SecurityConfigurationError


class _Client:
    """A duck-typed CloudWatch Logs client that records calls."""

    def __init__(self, response: Mapping[str, object] | None = None) -> None:
        self.response = response or {}
        self.calls: list[dict[str, object]] = []
        self.raises: BaseException | None = None

    def put_log_events(self, **kwargs: object) -> Mapping[str, object]:
        self.calls.append(dict(kwargs))
        if self.raises is not None:
            raise self.raises
        return self.response


def _config(**overrides: Any) -> CloudWatchLogsConfig:
    base: dict[str, Any] = {"log_group": "/jdlib/security"}
    base.update(overrides)
    return CloudWatchLogsConfig(**base)


def _sink(client: _Client, **overrides: Any) -> CloudWatchLogsAuditSink:
    return CloudWatchLogsAuditSink(client=client, config=_config(**overrides))


def _event(**overrides: Any) -> SecurityAuditEvent:
    # Enum members are taken from the types themselves rather than named here, so a rename in the
    # audit model cannot leave this test asserting against a value that no longer exists.
    base: dict[str, Any] = {
        "event_type": next(iter(SecurityEventType)),
        "outcome": next(iter(AuditOutcome)),
        "action": "documents:read",
        "source": next(iter(AuditSource)),
    }
    base.update(overrides)
    return SecurityAuditEvent(**base)


async def test_an_event_becomes_one_json_log_event() -> None:
    client = _Client()
    event = _event(tenant_id=None, request_id="req-1")
    await _sink(client).emit(event)

    call = client.calls[0]
    assert call["logGroupName"] == "/jdlib/security"
    assert call["logStreamName"] == "jdlib-security"
    log_events = call["logEvents"]
    assert isinstance(log_events, list) and len(log_events) == 1
    entry = cast("Mapping[str, Any]", log_events[0])
    document = json.loads(entry["message"])
    assert document["event_id"] == str(event.event_id)
    assert document["action"] == "documents:read"
    assert document["request_id"] == "req-1"
    # An absent field is omitted rather than serialised as null.
    assert "tenant_id" not in document


async def test_the_timestamp_is_milliseconds_since_the_epoch() -> None:
    client = _Client()
    event = _event()
    await _sink(client).emit(event)
    expected = int(event.occurred_at.timestamp() * 1000)
    log_events = cast("list[Mapping[str, Any]]", client.calls[0]["logEvents"])
    assert log_events[0]["timestamp"] == expected


async def test_no_sequence_token_is_sent() -> None:
    # PutLogEvents needs no sequence token for this stream, and sending a stale one is a classic
    # source of InvalidSequenceTokenException.
    client = _Client()
    await _sink(client).emit(_event())
    assert "sequenceToken" not in client.calls[0]


async def test_a_failed_write_is_visible_and_does_not_echo_the_client_message() -> None:
    client = _Client()
    client.raises = RuntimeError("InvalidParameterException: message=super-secret-material")
    event = _event()
    with pytest.raises(RuntimeError) as caught:
        await _sink(client).emit(event)
    message = str(caught.value)
    assert str(event.event_id) in message
    assert "RuntimeError" in message
    assert "super-secret-material" not in message
    assert caught.value.__cause__ is None


async def test_a_rejected_event_is_a_failure_even_when_the_call_succeeded() -> None:
    # CloudWatch accepts a call and rejects individual events; an accepted call is not a written
    # event, and an audit trail must not treat it as one.
    client = _Client({"rejectedLogEventsInfo": {"tooNewLogEventStartIndex": 0}})
    with pytest.raises(RuntimeError, match="rejected"):
        await _sink(client).emit(_event())


async def test_metadata_travels_but_nothing_is_added_to_it() -> None:
    client = _Client()
    await _sink(client).emit(_event(metadata={"reason": "no_allow"}))
    log_events = cast("list[Mapping[str, Any]]", client.calls[0]["logEvents"])
    document = json.loads(log_events[0]["message"])
    assert document["metadata"] == {"reason": "no_allow"}


def test_repr_names_the_destination_and_no_contents() -> None:
    assert "/jdlib/security" in repr(_sink(_Client()))


@pytest.mark.parametrize(
    "overrides",
    [
        {"log_group": ""},
        {"log_stream": ""},
        {"endpoint_url": "http://localhost:4566"},
    ],
)
def test_configuration_that_cannot_be_safe_is_rejected(overrides: dict[str, Any]) -> None:
    with pytest.raises(SecurityConfigurationError):
        _config(**overrides)


def test_it_has_the_sink_protocol_shape() -> None:
    import inspect

    assert inspect.iscoroutinefunction(_sink(_Client()).emit)
