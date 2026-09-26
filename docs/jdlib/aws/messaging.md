---
guide: aws
authority: docs/jdlib/aws/research-sources.md
modules: []
exports: []
test_files: []
---

# Messaging (SQS, SNS, EventBridge): not applicable, and why that is the honest answer

> **Design authority:** [the AWS capability matrix](aws-capability-matrix.md) and
> [the research sources](research-sources.md). Classified **NOT_APPLICABLE**.

## The verdict

The interface audit for section 29 found **no message-queue or event-publisher abstraction** in the
library, and the directive explicitly warns against adding all three messaging services by default.
Adapting a capability the library does not have is not adaptation; it is invention. So there is no
adapter, and this page records the reasoning and the semantics a deployment must handle itself.

## What the library does have, and what it is not

The audit trail is a **security event sink**, not an event bus: it records what happened for audit,
and its contract does not promise delivery, ordering or fan-out to consumers. Treating it as a
publisher would be a category error — the queue would inherit a security guarantee it was never
given.

`persistence/uow.py` is a unit of work, not an outbox. A transactional outbox — where a domain event
is written in the same transaction as the state change and published afterwards — is a real pattern
and a real capability, and this library does not have it. Naming the difference matters, because
"we publish after commit" and "the database and the broker agree" are different guarantees.

## What a deployment must handle if it adds a queue

| Concern | Why it matters |
| --- | --- |
| At-least-once delivery | SQS standard queues can deliver a message more than once, so consumers must be idempotent |
| Visibility timeout | a message is invisible while being processed; a slow consumer causes redelivery, not a lost message |
| Dead-letter queues | after the receive count is exhausted, an undeliverable message needs somewhere to go that a human will look at |
| Ordering | SQS FIFO and EventBridge ordering guarantees differ from standard queues; "in order" must be a deliberate choice |
| Poison messages | a message that always fails must not be retried forever |
| Payload limits and retention | 256 KB per SQS message, and a retention window that bounds how long a consumer may be down |

## What would change the verdict

A decision to give the library an outbox or a publisher — that is, a capability with its own
contract, its own failure semantics and a reason to exist — at which point an SQS, SNS or EventBridge
adapter becomes an adapter. The comparison to make at that point is not "which service is nicer" but
"what delivery guarantee does the contract promise": at-least-once with a DLQ, ordered fan-out, or
best-effort notification are three different contracts and only one of them is usually wanted.
