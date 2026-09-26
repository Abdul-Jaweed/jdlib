# The portal, reviewed from four chairs

The directive asks whether four readers can answer their questions from this documentation. The
honest test is not whether a page mentions a topic, but whether the reader can get from the question
to an answer without leaving the site. Each section below names the questions, the pages that answer
them, and what the review changed.

## Developer: can I build my first JDLib application?

| Question | Where the answer is |
|---|---|
| How do I install it, and what do I need running? | [Install](../getting-started/installation.md), [Quickstart](../getting-started/quickstart.md) |
| How do I configure the database and the tenant? | [Configuration](../getting-started/configuration.md), [CLI reference](../reference/cli-reference.md) |
| How do I scope a query to the tenant? | [Tenancy](../jdlib/features/tenancy.md), [Resource management](../jdlib/features/resource-management.md) |
| How do I add an endpoint, a permission, or a table? | the [guides](../guides/add-an-endpoint.md) |
| How do I test it without a database? | [Testing](../development/testing.md), [Test kit](../jdlib/features/tenancy.md) |
| What does a failure look like? | [Error codes](../reference/error-codes.md), [Troubleshooting](../operations/troubleshooting.md) |

**What this review changed.** The guides and the quickstart were written *after* this question was
asked, and every command in them is checked against the repository by
`tests/unit/test_example_docs.py`, which fails when a page documents a command the repository cannot
run.

## Architect: can I understand the complete architecture?

| Question | Where the answer is |
|---|---|
| What are the pieces, and how do they fit? | [High-level architecture](../architecture/high-level-architecture.md), [Component architecture](../architecture/component-architecture.md) |
| Where does tenant data live, and what is derived? | [Data architecture](../architecture/data-architecture.md) |
| What happens to one request, start to finish? | [Request lifecycle](../architecture/request-lifecycle.md) |
| Why is it built this way, and what was rejected? | [Architecture decisions](../development/architecture-decisions.md), [long-form reference](../architecture/long-form-reference.md) |
| What does a real deployment look like? | [Example architecture](../jdlib/architecture/example-architecture.md), [Deployment](../operations/deployment.md) |

**What this review changed.** The component view had no diagram of the *deployment* topology - only
prose about it. [Deployment](../operations/deployment.md) now draws it, and the MCP page draws the
invocation chain it describes.

## Security engineer: can I understand the boundaries and the controls?

| Question | Where the answer is |
|---|---|
| Where does the tenant come from, and what is refused? | [Security architecture](../architecture/security-architecture.md), [Tenancy](../jdlib/features/tenancy.md) |
| What does authorization decide, and on what? | [Authorization](../jdlib/features/authorization.md), [Security model](../jdlib/security-model.md) |
| What is written down, and what is never written down? | [Audit](../jdlib/features/audit.md), [Observability](../observability/overview.md) |
| What happens when a dependency is degraded? | [Failure modes](../reliability/failure-modes.md) |
| How is any of this proven? | [Security review](../jdlib/examples/security-review.md), [threat model](../threat-model/README.md), [the review's citations](../jdlib/examples/security-review.md) |

**What this review changed.** The reliability section's failure-mode table said what happens when a
dependency is down, but not what a *degraded* policy engine means. It does now: a degraded decision
is a refusal, and the page says so where a reader looking for a retry would find it.

## Operations engineer: can I deploy, monitor, troubleshoot, and recover?

| Question | Where the answer is |
|---|---|
| In what order do I bring it up? | [Deployment](../operations/deployment.md) |
| How do I know it is ready, and not merely up? | [Health and readiness](../operations/health-and-readiness.md) |
| What do I watch, and what does a bad value mean? | [Metrics](../observability/metrics.md), [Failure modes](../reliability/failure-modes.md) |
| Something is broken - what now? | [Troubleshooting](../operations/troubleshooting.md), [Incident response](../operations/incident-response.md) |
| Is this deployment complete? | [Production checklist](../operations/production-checklist.md) |
| How do I ship the next revision without dropping requests? | [Shutdown and draining](../reliability/shutdown.md) |

**What this review changed.** The troubleshooting page is a symptom table, and every row names the
evidence that distinguishes it - because "check the logs" is not a runbook. The production checklist
names, for each line, the artifact or command that answers it.

## Where the review found a gap and left it visible

The [documentation test matrix](documentation-test-matrix.md) earns its ticks from the tree, and one
cell is honestly empty: no test file names `jdlib.observability`. The signals are covered through
`jdlib.security.telemetry` and `jdlib.security.tracing`, which do have tests. The matrix prints the
gap and the explanation rather than a tick, which is the point of generating it.
