"""Job envelopes: a tenant token with a job identity, and the chain that revalidates it.

`EnvelopeCodec` already signs a tenant context and refuses an expired one, and
`ContextPropagator.reconstruct` already walks the chain a job must walk - principal active,
tenant present, entitlement held, tenant servable. Nothing here rebuilds any of that.

A queue needs two things a request does not. The same delivery may arrive twice, so a job
needs an identity to detect a replay. And a job may sit in a queue while the authority that
authorized it is withdrawn, so the envelope carries its own lifetime and is revalidated at
execution rather than at enqueue. Both are signed together with the tenant token, so a
rewritten expiry fails the same way a rewritten tenant would.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from collections.abc import Awaitable, Callable, MutableSet
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from jdlib.context import Clock, EnvelopeCodec, TenantContext
from jdlib.errors import JdlibError
from jdlib.tenancy.jobs import ContextPropagator


class JobEnvelopeError(JdlibError):
    """Base for every refusal in this module."""


class EnvelopeForgeryError(JobEnvelopeError):
    """The envelope is not authentic: tampered, signed with another key, or unreadable."""


class EnvelopeExpiredError(JobEnvelopeError):
    """The job outlived the lifetime it was issued with."""


class EnvelopeReplayError(JobEnvelopeError):
    """This delivery has already been executed."""


class JobRevokedError(JobEnvelopeError):
    """The job was revoked after it was enqueued."""


def _sign(key: str, *, job_id: str, issued_at: datetime, expires_at: datetime, token: str) -> str:
    payload = "\n".join((job_id, issued_at.isoformat(), expires_at.isoformat(), token)).encode()
    return hmac.new(key.encode(), payload, hashlib.sha256).hexdigest()


@dataclass(frozen=True, slots=True)
class JobEnvelope:
    """A signed unit of deferred work: a job identity over an already-signed tenant token."""

    job_id: str
    token: str
    issued_at: datetime
    expires_at: datetime
    signature: str

    @classmethod
    def issue(
        cls,
        *,
        codec: EnvelopeCodec,
        context: TenantContext,
        job_id: str,
        ttl: timedelta,
        key: str,
        clock: Clock,
    ) -> JobEnvelope:
        """Build an envelope from a tenant context.

        A job id is required rather than defaulted: without one a replay is undetectable, and
        an unidentified job is not a safer job.
        """
        if not isinstance(job_id, str) or not job_id.strip():
            raise JobEnvelopeError("a job id is required: a replay cannot be detected without one")
        if ttl <= timedelta(0):
            raise JobEnvelopeError("a job's lifetime must be positive")
        issued_at = clock.now()
        token = codec.encode(context)
        expires_at = issued_at + ttl
        return cls(
            job_id=job_id,
            token=token,
            issued_at=issued_at,
            expires_at=expires_at,
            signature=_sign(
                key, job_id=job_id, issued_at=issued_at, expires_at=expires_at, token=token
            ),
        )

    def to_token(self) -> str:
        payload = json.dumps(
            {
                "job_id": self.job_id,
                "token": self.token,
                "issued_at": self.issued_at.isoformat(),
                "expires_at": self.expires_at.isoformat(),
                "signature": self.signature,
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        return base64.urlsafe_b64encode(payload).decode()

    @classmethod
    def parse(cls, wire: str, *, key: str) -> JobEnvelope:
        """Decode and verify. Anything unreadable or unauthentic is refused here."""
        try:
            payload = json.loads(base64.urlsafe_b64decode(wire.encode()).decode())
            envelope = cls(
                job_id=str(payload["job_id"]),
                token=str(payload["token"]),
                issued_at=datetime.fromisoformat(str(payload["issued_at"])),
                expires_at=datetime.fromisoformat(str(payload["expires_at"])),
                signature=str(payload["signature"]),
            )
        except Exception as exc:
            raise EnvelopeForgeryError("the envelope could not be read") from exc
        expected = _sign(
            key,
            job_id=envelope.job_id,
            issued_at=envelope.issued_at,
            expires_at=envelope.expires_at,
            token=envelope.token,
        )
        if not hmac.compare_digest(expected, envelope.signature):
            raise EnvelopeForgeryError(
                "the envelope is not authentic: its signature does not cover its contents"
            )
        return envelope


JobHandler = Callable[..., Awaitable[Any]]


class JobDispatcher:
    """Runs a job only after the envelope and the authority behind it both check out.

    The order matters and is deliberate: authenticity, then lifetime, then identity, then
    revocation, then the tenant chain. A cheap local check precedes a lookup, and the handler
    runs only if every one of them passes - a failure reports an error rather than running the
    work and mentioning it afterwards.
    """

    def __init__(
        self,
        *,
        propagator: ContextPropagator,
        key: str,
        clock: Clock,
        is_revoked: Callable[[str], bool] | None = None,
        seen: MutableSet[str] | None = None,
    ) -> None:
        self._propagator = propagator
        self._key = key
        self._clock = clock
        self._is_revoked = is_revoked
        self._seen: MutableSet[str] = seen if seen is not None else set()

    async def execute(self, wire: str, handler: JobHandler, *args: object, **kwargs: object) -> Any:
        envelope = JobEnvelope.parse(wire, key=self._key)
        if envelope.expires_at <= self._clock.now():
            raise EnvelopeExpiredError(
                f"job {envelope.job_id} expired at {envelope.expires_at.isoformat()}"
            )
        if envelope.job_id in self._seen:
            raise EnvelopeReplayError(f"job {envelope.job_id} has already been executed")
        if self._is_revoked is not None and self._is_revoked(envelope.job_id):
            raise JobRevokedError(f"job {envelope.job_id} was revoked after it was enqueued")

        context = await self._propagator.reconstruct(envelope.token)

        from jdlib.context import context_scope

        self._seen.add(envelope.job_id)
        with context_scope(context):
            return await handler(*args, **kwargs)
