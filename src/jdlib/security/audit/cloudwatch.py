"""CloudWatch Logs audit sink (AWS directive §18).

A `SecurityEventSink` that writes each event to CloudWatch Logs as one JSON document. The audit
sink in the database (`TransactionAuditSink`) is the fail-closed one that shares the caller's
transaction; this is the external one, for deployments that ship security events to a log platform
where they are retained, searched and alerted on.

Two decisions are deliberate and worth stating, because an audit trail is where "reasonable
defaults" cause the most damage:

* **Fail-closed, visibly.** `emit` raises when the write fails. A sink that swallowed the failure
  would leave an operation recorded nowhere while the caller believed it was audited -- the one
  failure an audit trail must never have. A deployment that prefers best-effort can wrap this sink
  in its own, and the choice is then explicit in code rather than hidden here.
* **No secret material.** The event's `metadata` is already sanitized by the audit model, and this
  sink adds nothing to it: the document is the event's own fields, serialised. A client exception's
  message is never echoed into the event or into a raised error, because a CloudWatch error can
  quote the payload it rejected.

The client is injected and duck-typed, the same idiom as the gateway, policy and secret transports,
so this sink is testable without AWS and boto3 stays out of the core dependency set.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Protocol

from pydantic import BaseModel, ConfigDict, model_validator

from jdlib.security.audit.events import SecurityAuditEvent
from jdlib.security.errors import SecurityConfigurationError


class CloudWatchLogsClient(Protocol):
    """The one client method this sink needs."""

    def put_log_events(self, **kwargs: object) -> Mapping[str, object]: ...


class CloudWatchLogsConfig(BaseModel):
    """CloudWatch Logs settings (AWS directive §18)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    log_group: str
    log_stream: str = "jdlib-security"
    region: str | None = None
    endpoint_url: str | None = None

    @model_validator(mode="after")
    def _validate(self) -> CloudWatchLogsConfig:
        if not self.log_group:
            raise SecurityConfigurationError("log_group must not be empty")
        if not self.log_stream:
            raise SecurityConfigurationError("log_stream must not be empty")
        if self.endpoint_url is not None and not self.endpoint_url.startswith("https://"):
            raise SecurityConfigurationError("endpoint_url must use https")
        return self


class CloudWatchLogsAuditSink:
    """Writes security events to CloudWatch Logs."""

    def __init__(
        self,
        *,
        client: CloudWatchLogsClient,
        config: CloudWatchLogsConfig,
    ) -> None:
        self._client = client
        self._config = config

    def __repr__(self) -> str:
        """Name the destination, never the contents."""
        return (
            f"CloudWatchLogsAuditSink(log_group={self._config.log_group!r}, "
            f"log_stream={self._config.log_stream!r})"
        )

    async def emit(self, event: SecurityAuditEvent) -> None:
        """Write one event. Raises when the write fails; see the module docstring."""
        try:
            response = self._client.put_log_events(
                logGroupName=self._config.log_group,
                logStreamName=self._config.log_stream,
                logEvents=[
                    {
                        "timestamp": _epoch_millis(event.occurred_at),
                        "message": json.dumps(
                            _document(event), sort_keys=True, separators=(",", ":")
                        ),
                    }
                ],
            )
        except Exception as exc:  # noqa: BLE001 - a failed audit write must not be silent
            # The event id is safe to name; the client's message is not, because a rejected payload
            # can be quoted back inside it.
            raise RuntimeError(
                f"audit event {event.event_id} could not be written to "
                f"{self._config.log_group!r} ({type(exc).__name__})"
            ) from None
        rejected = response.get("rejectedLogEventsInfo")
        if rejected:
            # CloudWatch accepts a call and rejects individual events; an accepted call is not a
            # written event, so this is a failure like any other.
            raise RuntimeError(f"audit event {event.event_id} was rejected by CloudWatch Logs")


def _epoch_millis(moment: datetime) -> int:
    """CloudWatch timestamps are milliseconds since the epoch."""
    return int(moment.astimezone(UTC).timestamp() * 1000)


def _document(event: SecurityAuditEvent) -> dict[str, object]:
    """The event as a JSON-serialisable document, with absent fields omitted.

    Nothing is added: the fields are the event's own, and `metadata` has already been through the
    audit model's sanitiser, so this sink cannot introduce a leak the model did not already refuse.
    """
    document: dict[str, object] = {
        "event_id": str(event.event_id),
        "event_type": str(event.event_type),
        "outcome": str(event.outcome),
        "action": event.action,
        "source": str(event.source),
        "occurred_at": event.occurred_at.astimezone(UTC).isoformat(),
    }
    for name in (
        "tenant_id",
        "principal_id",
        "principal_kind",
        "resource_type",
        "resource_id",
        "request_id",
        "correlation_id",
        "trace_id",
    ):
        value = getattr(event, name)
        if value is not None:
            document[name] = str(value)
    if event.metadata:
        document["metadata"] = dict(event.metadata)
    return document


__all__ = [
    "CloudWatchLogsAuditSink",
    "CloudWatchLogsClient",
    "CloudWatchLogsConfig",
]
