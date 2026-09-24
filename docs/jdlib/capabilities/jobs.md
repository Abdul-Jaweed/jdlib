---
capability: jobs
namespace: jdlib.tenancy
errors_module: jdlib.tenancy.job_envelope
modules:
  - src/jdlib/tenancy/job_envelope.py
exports:
  - JobDispatcher
  - JobEnvelope
refusals:
  - EnvelopeExpiredError
  - EnvelopeForgeryError
  - EnvelopeReplayError
  - JobEnvelopeError
  - JobRevokedError
test_files:
  - tests/unit/test_job_envelope.py
test_functions: 14
---
# Background jobs: an envelope whose authority is re-checked at execution

## What it is

A queue needs two things a request does not. The same delivery may arrive twice, so the envelope
carries a **job id**; a job may wait in a queue while the authority behind it is withdrawn, so it
carries its own **lifetime** and is revalidated at execution.

```python
token = JobEnvelope.issue(codec=codec, context=tenant_context, job_id="job-0001",
                          ttl=timedelta(minutes=5), key=signing_key, clock=clock).to_token()

dispatcher = JobDispatcher(propagator=propagator, key=signing_key, clock=clock)
await dispatcher.execute(token, handler)
```

## The decisions that carry weight

**Nothing is rebuilt.** The tenant token, its signature, its TTL and its clock were already
`EnvelopeCodec`'s, and the chain a job must walk - principal active, tenant present, entitlement
held, tenant servable - was already `ContextPropagator.reconstruct`'s.

**The job's own fields are signed with the tenant token**, so a rewritten expiry fails as a
rewritten tenant would. Swapping the *identity* is the forgery that matters, because that is how
replay detection would be defeated.

**A job id is required rather than defaulted**: an unidentified job is not a safer job, it is an
undetectable replay.

**The chain runs authenticity, lifetime, identity, revocation, then tenancy** - a cheap local
check before a lookup. Fail closed is tested as *work not happening*: one case per failure mode,
each asserting the handler never ran. That ordering is itself a defence, and it was discovered by
a red-team test that accidentally proved it rather than the attack it named.

**Refusals are audited before they are raised** - `AUTHZ_DENY` on a delegation refusal,
`PRIVILEGE_USED` on acceptance - so the record exists even though the caller sees only the
exception.

## Evidence

14 test functions across `tests/unit/test_job_envelope.py`, run with the project gate:

```bash
.venv/Scripts/python.exe -m pytest tests/unit/test_job_envelope.py -q
```

Parametrized cases expand these functions further; the counts here are
functions, which is what the documentation check verifies.

## Limits

No broker, no retry budget, no dead-letter queue and no shutdown drain: the envelope is the
contract, and the transport is the application's. These are the open reliability gaps recorded in
`successor/06-reliability-inventory.md`, not features in disguise.
