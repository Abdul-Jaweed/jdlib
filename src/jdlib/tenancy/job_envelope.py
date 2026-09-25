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

import asyncio
import base64
import hashlib
import hmac
import json
import uuid
from collections.abc import Awaitable, Callable, MutableSet
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from jdlib.context import Clock, EnvelopeCodec, TenantContext, context_scope
from jdlib.errors import JdlibError
from jdlib.reliability import CircuitBreaker, RetryBudget
from jdlib.reliability.policy import backoff_seconds, is_retryable_failure
from jdlib.tenancy.dead_letter import DeadLetter, DeadLetterStore
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


class JobAttemptsExhaustedError(JobEnvelopeError):
    """The handler failed and the dispatcher will not run this job again.

    Raised with the last failure as ``__cause__``: the caller needs the reason as much as it
    needed the error, and the error is still there.
    """


@dataclass(frozen=True, slots=True)
class JobRetry:
    """How many attempts a job gets, and how long to wait between them.

    ``max_attempts`` defaults to one, which is the behaviour this dispatcher had before retries
    existed: no retry, no dead letter, and the handler's own error raised unchanged.
    """

    max_attempts: int = 1
    backoff: timedelta = timedelta(seconds=1)

    def __post_init__(self) -> None:
        if self.max_attempts < 1:
            raise JobEnvelopeError("a job must be attempted at least once")
        if self.backoff < timedelta(0):
            raise JobEnvelopeError("a backoff cannot be negative")


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
        retry: JobRetry | None = None,
        dead_letters: DeadLetterStore | None = None,
        retry_budget: RetryBudget | None = None,
        breaker: CircuitBreaker | None = None,
        sleeper: Callable[[float], Awaitable[None]] | None = None,
        jitter: Callable[[float, float], float] | None = None,
    ) -> None:
        self._propagator = propagator
        self._key = key
        self._clock = clock
        self._is_revoked = is_revoked
        self._seen: MutableSet[str] = seen if seen is not None else set()
        self._retry = retry if retry is not None else JobRetry()
        self._dead_letters = dead_letters
        self._retry_budget = retry_budget
        self._breaker = breaker
        self._sleeper = sleeper
        self._jitter = jitter

    async def execute(
        self, wire: str, handler: JobHandler, *args: object, **kwargs: object
    ) -> Any:
        """Run the job, retrying it while that is a decision this dispatcher can defend.

        The preflight is unchanged and runs once - authenticity, lifetime, identity, revocation -
        because those are properties of the *delivery*, not of an attempt. A retry must not look
        like a replay, so the job id is marked when the first attempt starts, and a second
        delivery of the same wire is still refused. What is re-checked per attempt is the part
        that time can change: the envelope's lifetime, and the authority behind it.

        Retries are off unless ``JobRetry`` asks for them, and then only a failure the taxonomy
        calls retryable is repeated; the rest are recorded and re-raised. Every give-up is a
        decision, and every decision the dispatcher made is written down.
        """
        envelope = JobEnvelope.parse(wire, key=self._key)
        if envelope.expires_at <= self._clock.now():
            raise EnvelopeExpiredError(
                f"job {envelope.job_id} expired at {envelope.expires_at.isoformat()}"
            )
        if envelope.job_id in self._seen:
            raise EnvelopeReplayError(f"job {envelope.job_id} has already been executed")
        if self._is_revoked is not None and self._is_revoked(envelope.job_id):
            raise JobRevokedError(f"job {envelope.job_id} was revoked after it was enqueued")

        # From here the delivery is authentic and unspent, so everything that happens is a
        # decision this dispatcher made - and only these are worth recording anywhere.
        self._seen.add(envelope.job_id)
        wait = self._sleeper or asyncio.sleep
        choose = self._jitter or (lambda low, high: (low + high) / 2)
        known_tenant: uuid.UUID | None = None

        for attempt in range(1, self._retry.max_attempts + 1):
            try:
                context = await self._revalidate(envelope)
            except Exception as exc:
                # The lifetime ran out or the authority was withdrawn while the job was failing:
                # not something a second attempt of *this* execution changes, so it stops - and
                # the job is recorded, because it was already half-run when it stopped.
                if attempt > 1:
                    await self._record(envelope, known_tenant, attempt, "refused", exc)
                raise
            known_tenant = context.tenant_id

            if self._breaker is not None and not self._breaker.allow():
                # The dependency this job talks to is refusing calls, so another attempt now
                # would be another call it refuses. That is a give-up like any other, and it is
                # recorded as the *condition*: no handler ran, so there is no exception to name.
                await self._record_type(
                    envelope, known_tenant, attempt, "breaker", "CircuitBreakerOpen"
                )
                raise JobAttemptsExhaustedError(
                    f"job {envelope.job_id} was not attempted: "
                    "the circuit for its dependency is open"
                )

            try:
                with context_scope(context):
                    result = await handler(*args, **kwargs)
            except Exception as exc:
                if self._breaker is not None:
                    # A failure the handler saw is a failure of what the breaker guards, whether
                    # or not this dispatcher is configured to retry it.
                    self._breaker.record_failure()
                if self._retry.max_attempts == 1:
                    # Retries were never configured: nothing was decided here, so nothing is
                    # recorded and the handler's own error is raised unchanged.
                    raise
                if not is_retryable_failure(exc):
                    await self._record(envelope, known_tenant, attempt, "permanent", exc)
                    raise
                if attempt == self._retry.max_attempts:
                    await self._record(envelope, known_tenant, attempt, "exhausted", exc)
                    raise JobAttemptsExhaustedError(
                        f"job {envelope.job_id} failed {attempt} time(s) and will not be retried"
                    ) from exc
                if self._retry_budget is not None and not self._retry_budget.take(
                    now=self._clock.now()
                ):
                    await self._record(envelope, known_tenant, attempt, "budget", exc)
                    raise JobAttemptsExhaustedError(
                        f"job {envelope.job_id} was not retried: the shared retry budget is spent"
                    ) from exc
                await wait(backoff_seconds(self._retry.backoff, attempt, choose))
            else:
                if self._breaker is not None:
                    self._breaker.record_success()
                return result

        raise JobAttemptsExhaustedError(  # pragma: no cover - the loop always returns or raises
            f"job {envelope.job_id} ran out of attempts"
        )

    async def _revalidate(self, envelope: JobEnvelope) -> TenantContext:
        """Lifetime and authority for the attempt about to run - the attempt, not the delivery."""
        if envelope.expires_at <= self._clock.now():
            raise EnvelopeExpiredError(
                f"job {envelope.job_id} expired at {envelope.expires_at.isoformat()}"
            )
        return await self._propagator.reconstruct(envelope.token)

    async def _record(
        self,
        envelope: JobEnvelope,
        tenant_id: uuid.UUID | None,
        attempts: int,
        reason: str,
        exc: BaseException,
    ) -> None:
        """Write down a give-up. The error's *type* is recorded; its message never is."""
        await self._record_type(envelope, tenant_id, attempts, reason, type(exc).__name__)

    async def _record_type(
        self,
        envelope: JobEnvelope,
        tenant_id: uuid.UUID | None,
        attempts: int,
        reason: str,
        error_type: str,
    ) -> None:
        """Write down a give-up that names a condition rather than an exception."""
        if self._dead_letters is None:
            return
        await self._dead_letters.record(
            DeadLetter(
                job_id=envelope.job_id,
                tenant_id=tenant_id,
                attempts=attempts,
                reason=reason,
                error_type=error_type,
                recorded_at=self._clock.now(),
            )
        )
