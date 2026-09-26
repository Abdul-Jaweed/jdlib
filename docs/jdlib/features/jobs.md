---
guide: jobs
authority: docs/jdlib/capabilities/jobs.md
modules:
  - src/jdlib/tenancy/__init__.py
  - src/jdlib/tenancy/dead_letter.py
  - src/jdlib/tenancy/job_envelope.py
  - src/jdlib/tenancy/jobs.py
  - src/jdlib/tenancy/middleware.py
  - src/jdlib/tenancy/resolution.py
exports:
  - JobEnvelope
  - JobDispatcher
  - EnvelopeForgeryError
  - EnvelopeExpiredError
  - EnvelopeReplayError
  - JobRevokedError
  - JobAttemptsExhaustedError
  - JobRetry
test_files:
  - tests/unit/test_job_envelope.py
  - tests/unit/test_job_dispatcher_breaker.py
  - tests/unit/test_job_retry_dead_letter.py
  - tests/unit/test_jobs.py
---
# Background jobs

> **Design authority:** [`docs/jdlib/capabilities/jobs.md`](../capabilities/jobs.md) — this guide is the developer-facing
> shape of that page, not a second authority for it. Where the two disagree, the authority page and
> the code win.

## What it is

An envelope for work that runs later: a job id, a lifetime, the authority it was created under, and a dispatcher that re-checks that authority at execution time.

## Why it exists

A queue breaks two assumptions a request relies on. The same delivery may arrive twice, so the work must be idempotent by job id; and the authority behind the work may be withdrawn while it waits, so a job must not execute on authority that no longer exists.

## When to use it

When work must outlive a request: an export, a migration, a notification, a re-projection. Especially when the work is tenant-scoped and the tenant can be suspended between enqueue and execution.

## When not to use it

For work that must complete inside the request's transaction, and for anything a caller is waiting on -- a queue is not a way to make a slow request fast.

## How it works

`JobEnvelope` carries the job's identity, its tenant, its deadline and a signature over those; `JobDispatcher` verifies the envelope (`EnvelopeForgeryError`, `EnvelopeExpiredError`, `EnvelopeReplayError`), re-resolves the tenant's authority, and runs the job under that context -- refusing if the tenant is suspended (`JobRevokedError`). Retries are bounded (`JobAttemptsExhaustedError`) and `JobRetry` decides what is retryable; exhausted jobs go to the dead-letter store.

## Architecture

`tenancy/job_envelope.py` (the envelope and its verifier), `tenancy/jobs.py` (dispatch and retry), `tenancy/dead_letter.py` (what could not be completed). The queue itself is the deployment's choice -- the library's business is the envelope and the authority check.

## Example

**The example application does not use background jobs.** This guide documents the library's seam and the shape a deployment follows; the evidence for the claims above is the library's own suites, listed under Testing, rather than an example path. Saying so is the point: a guide that invented an example would be documenting something nobody has run.

## Security

The envelope is signed, so a forged job is refused; it is single-use, so a replay is refused; and its authority is re-checked at execution, so a revoked tenant cannot be acted on by work queued earlier. The job runs inside a tenant context, exactly as a request does.

## Reliability

Retries are bounded with backoff, the dispatcher goes through a circuit breaker when its dependency is failing, and a job that cannot succeed lands in the dead-letter store with its envelope -- which is what makes a stuck queue diagnosable rather than silent.

## Observability

Each job is a span with the job id, the tenant and the attempt number, joined to the request that enqueued it by correlation id.

## Audit

A job's execution is audited under the authority it ran with, and a refusal (expired, replayed, revoked) is a security event rather than an application log line.

## Configuration

The queue and its credentials are configuration; the envelope's lifetime and retry policy are the application's decision, declared where the job is enqueued.

## Testing

`tests/unit/test_job_envelope.py` covers the envelope and every refusal; `test_job_dispatcher_breaker.py`, `test_job_retry_dead_letter.py` and `test_jobs.py` cover dispatch, retries and the dead-letter path.

## Common mistakes

Running a job without a tenant context; treating the queue's delivery guarantee as idempotence; retrying a non-idempotent write; letting an envelope's lifetime outlive the credential that created it; dropping exhausted jobs instead of dead-lettering them.

## Production checklist

Bound the envelope's lifetime to something shorter than your credential's; alert on the dead-letter store rather than only on failures; make every handler idempotent by job id; and rehearse a tenant suspension to confirm queued work stops.
