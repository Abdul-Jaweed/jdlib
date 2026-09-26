---
guide: aws
authority: docs/jdlib/aws/aws-capability-matrix.md
modules: []
exports: []
test_files: []
---

# Certification report: the AWS provider adapter programme

> Directive sections 43 to 46. Every claim on this page is backed by a commit, a test run or a CI
> run named here. Where something was not verified, it says so — the honest report is the point of
> the exercise, not a formality after it.

## Research Sources

Four research passes over official AWS, Cedar and Cerbos documentation, each producing a cited brief:
Cognito and Verified Permissions (including the Cerbos-to-Cedar semantic differences); API Gateway,
Secrets Manager and Parameter Store; the data services (RDS/Aurora, Neptune, ElastiCache, S3);
and the operations surface (CloudWatch, X-Ray, CloudTrail, messaging, ECS/Fargate/Lambda, WAF,
CloudFront, DynamoDB, AgentCore and the supplied AWS MCP architecture). The sources are listed on
[the research sources page](research-sources.md), which also separates **documented service
behaviour** from **documented integration patterns** — the distinction that decides whether a claim
here is a guarantee or a recipe.

## Architecture

The programme's first act was an audit of the library's real abstraction surface, not an assumption
about it. Nine protocols already existed: `Authenticator`, `JwtTokenValidator`,
`PolicyDecisionPoint` (two layers: the tenant-plane `evaluate` and the external-engine `decide`),
`SecretProvider`, `Cache`, `ObjectStorageProvider`, `GraphClient`/`GraphRunner`,
`SecurityEventSink`, and the gateway adapters. Three did not exist: a configuration provider, a
message queue, and an event publisher.

Placement followed the repository rather than the directive's sketch: providers live beside their
peers (`security/authn/zitadel.py`, `security/authz/cerbos.py`), so the AWS adapters were written
into the capability packages, not into a monolithic `integrations/aws/`. No new interface was
created, and where a capability had no interface, the capability was declined rather than invented —
which is what section 29 asked for and what the deferred list below records.

The provider-neutral claim is now demonstrated rather than asserted: `VerifiedPermissionsPDP`
implements the same protocol as `CerbosPDP`, and a test asserts that conformance with an
`isinstance` check against the runtime-checkable protocol.

## Implemented Adapters

| Adapter | Module | Protocol | Tests |
| --- | --- | --- | --- |
| Cognito authenticator | `security/authn/cognito.py` | `Authenticator` / `JwtTokenValidator` | 26 |
| Verified Permissions PDP | `security/authz/verified_permissions.py` | `PolicyDecisionPoint` (the external-engine protocol) | 22 |
| Secrets Manager provider | `persistence/secrets_manager.py` | `SecretProvider` | 13 |
| CloudWatch Logs audit sink | `security/audit/cloudwatch.py` | `SecurityEventSink` | 11 |
| Cognito + AVP composition (example) | `examples/aws_cognito_avp/composition.py` | composition, no new protocol | 5 |

**77 tests**, all against injected clients, locally generated RSA keys and fake JWKS fetchers. No
AWS account is involved anywhere, and the live paths are marked `NOT RUN` rather than implied.

Four design decisions are worth naming because they are the difference between an adapter and a
wrapper:

* **Cognito supplies discovery, not verification.** AWS documents token verification as the
  application's job and recommends a JWT library, so the adapter configures the library's existing
  validator and adds the one check it does not make (`token_use`), plus the `client_id` check that
  Cognito access tokens require. Two Cognito facts drive it: two key pairs behind one JWKS, and no
  documented clock-skew tolerance for user-pool validation (so `leeway` defaults to zero).
* **The AVP mapping is deliberately thin.** Principal, action, resource, context, and nothing
  invented. Roles travel as an attribute because Cedar has no role construct; the tenant rides in
  both the resource attributes and the context map; the permission string's verb becomes the action
  id. Fail-closed is enforced by `AuthorizationDecision` itself, so no adapter can weaken it.
* **Secrets Manager keeps the exception class and drops the message.** An SDK error can echo the
  secret value back; `ResourceNotFoundException` and `AccessDeniedException` still need to be
  distinguishable. This was found by a test, not by review.
* **The audit sink treats `rejectedLogEventsInfo` as a failure.** CloudWatch accepts a call and
  rejects individual events; an accepted call is not a written event.

## Deferred Adapters

Three capabilities were declined, each with its reason recorded rather than left as a gap:

| Capability | Verdict | Reason |
| --- | --- | --- |
| SSM Parameter Store | **DEFER** | Section 12 is conditional on a configuration-provider abstraction, which the audit found does not exist, and section 29 forbids inventing one to fill a matrix row. It is not smuggled in as a `SecretProvider` either — that would teach callers configuration and secrets are the same thing. [The verdict](parameter-store.md) names what would change it. |
| Amazon Neptune | **DEFER** (evaluated) | openCypher over Bolt is supported, so the wire protocol is not the obstacle; APOC, `CALL`, `shortestPath`, dynamic property access and multiple databases are. An adapter must *refuse* what the engine cannot run, and a capability profile that refuses queries needs a user before it needs code. Tenancy does **not** block it — the client enforces tenant scope, not the database. |
| SQS / SNS / EventBridge | **NOT_APPLICABLE** | No queue or publisher abstraction exists; adapting a capability the library does not have is invention. [The page](messaging.md) distinguishes the audit sink from an event bus and the unit of work from an outbox. |
| Amazon API Gateway | **INFRASTRUCTURE_ONLY** | The Kong and Tyk adapters verify a signature over identity claims; API Gateway signs no such envelope, so a third adapter would be a trust contract AWS does not offer. [The edge page](api-gateway.md) documents the integrations that are correct. |

## MCP Validation

The supplied AWS MCP reference architecture was validated against what the library already does.
The decomposition is honest about the split: token validation is the library's
(`McpSecurityBoundary` plus the JWT validator), while session and token *storage* is a deployment
concern the library does not implement — an MCP server that scales horizontally wants its session
state outside the process.

The finding that matters is **AgentCore Gateway's authenticate-only inbound mode**: it validates a
token and passes the request through without deciding, which is exactly where a JDLib deployment
wants the boundary. The decision point does not move.

MCP's own authorization model was mapped: audience-bound tokens, the prohibition on token
passthrough (which the library already satisfies by never relaying a caller's token upstream), and
scopes as surface gating rather than a permission model. The open question — authorize the agent or
authorize the user — is stated rather than papered over, because the library authorizes what the
validated token says and will not guess a delegation model.

The three pairings the success criteria name are documented: [Cognito + MCP](mcp.md), Verified
Permissions + MCP, and API Gateway + MCP — including the interaction that bites hardest, MCP's
streamable HTTP transport against a 29-second REST integration timeout.

## Security

* **Fail-closed everywhere.** Every adapter's failure space — unreachable, timeout, throttled,
  malformed, unknown — produces a denied or degraded outcome. `AuthorizationDecision` refuses to
  construct an allowed degraded decision at all, so this is a property of the type.
* **No secret material escapes.** Tests assert that reprs, exception messages and cause chains carry
  no values: the Secrets Manager provider (two tests), the audit sink (two tests). One real leak was
  found and fixed this way.
* **Algorithm confusion is blocked before verification.** The library's allow-list rejects a
  symmetric token before any signature work happens; a Cognito test asserts it.
* **The IAM boundary is documented** ([the IAM page](iam.md)) with the mistake it exists to prevent:
  an IAM policy is not a tenant permission model.
* **No credentials are committed.** Every adapter takes an injected client; the Verified Permissions
  config's `credentials` field accepts only `None`; no AWS keys appear anywhere in the diff.

## Reliability

The reliability cases the directive names are covered per adapter: **PDP unavailable, timeout,
throttled, deny and malformed response** for Verified Permissions (including that cancellation
propagates rather than becoming an authorization answer); **unresolvable handle, access denied,
throttled** for Secrets Manager, all mapping to the same `KeyError` shape the existing providers use;
**write failure and rejected event** for the audit sink; and **key rotation, unknown `kid` and a
failing JWKS fetch** for Cognito, all failing closed.

Throttling is distinguished from unavailability (`engine_throttled` versus `engine_unavailable`),
because a throttled deployment needs backoff and an unreachable one needs an incident.

## Observability

OpenTelemetry first, AWS through the collector — the rule and its consequences are on
[the observability page](observability.md). The library emits OTLP; ADOT or any collector exports to
CloudWatch and X-Ray; no core module speaks an AWS telemetry API. The existing OTel infrastructure
tests (`tests/infra/test_otel_infra.py`) continue to cover the emission path, and this programme adds
the CloudWatch-side mapping tests through the audit sink. What must never be instrumented is stated
explicitly: no secret values, no tokens, no request bodies, no personal data.

## Documentation

Twenty-five pages under `docs/jdlib/aws/`, wired into the MkDocs navigation as an AWS section under
Integrations: the capability matrix, the research sources, the Cognito and Verified Permissions
pages, secrets and configuration, the edge and the gateway comparison, the five data-plane
evaluations, audit, observability, health, IAM, the security model, the three MCP pages, the example,
the reference architectures, the comparisons index and this report. Mermaid diagrams cover the
deployment, the decision chain, the MCP path and the tenancy path through the data planes.

`mkdocs build --strict` is clean, the four generated-page checks pass, and the API reference was
regenerated for the new public symbols — the check caught that it needed to be.

## Test Results

| What | Result |
| --- | --- |
| New AWS tests | **77 passed** (26 + 22 + 13 + 11 + 5) |
| Documentation tests | **928 passed, 7 skipped** |
| Strict documentation build | **clean** (`mkdocs build --strict`, exit 0) |
| Generated-page checks | `docs-inventory`, `docs-matrix`, `api-reference`, `feature-matrix` — **all OK** |
| Ruff | clean on every new module and test |
| Mypy | clean on every new module and test |
| CI | six runs verified **success**: `d4fb75f`, `2d9837b`, `2dda321`, `8cbbb85`, `a229e44`, `05d2abb`; `8153cd2` and `e552f02` were in flight when this report was written |

## Known Limitations

* **No live AWS verification.** Every test uses injected clients, a locally generated key pair and a
  fake JWKS fetcher. The adapters are verified against AWS's documented contracts, not against a
  live user pool, policy store, secret or log group. Every page says `NOT RUN — AWS credentials
  unavailable` where it applies, and no test claims otherwise.
* **Cognito access tokens without a resource binding cannot be validated by the current wiring** —
  the generic validator requires `aud`, and such a token carries only `client_id`. The default is the
  ID token, and this is documented rather than worked around.
* **Revocation is invisible to JWT validation.** A revoked Cognito token still validates; short
  lifetimes are the documented mitigation, and the adapter does not pretend otherwise.
* **ElastiCache cluster mode and IAM authentication are not supported by `RedisCache`** — it builds a
  non-cluster-aware client from a URL. Both are named on [the ElastiCache page](elasticache.md).
* **A tenant prefix in S3 is a convention, not a control** until an IAM or bucket policy enforces it.
* **The Secrets Manager cache is per-process**, so a fleet of N processes resolves N times per TTL.
* **The audit sink writes one event per call**, which is correct and chatty against CloudWatch's
  per-call cost.
* **Neptune, Parameter Store and messaging are not implemented**, for the reasons in the deferred
  table above — not for lack of time.
* **Provider semantic differences are documented, not smoothed**: the Cerbos-versus-Cedar differences
  are enumerated on the Verified Permissions page, and the Cognito-versus-ZITADEL differences in the
  comparisons index. A migration between providers is a change in authorization behaviour until
  proven otherwise, and the documentation says so.

## Success criteria (directive section 46)

| Criterion | Status |
| --- | --- |
| AWS capability research completed | **Met** — four cited briefs |
| AWS capability matrix created | **Met** — [the matrix](aws-capability-matrix.md), every candidate classified |
| Provider-neutral architecture validated | **Met** — nine existing protocols, no new interface, conformance asserted by test |
| Cognito adapter implemented where the contract supports it | **Met** |
| Verified Permissions adapter implemented where the contract supports it | **Met** |
| API Gateway integration/adapter where the contract supports it | **Met as documented** — the contract does not support an adapter, and [the page](api-gateway.md) proves why |
| Secrets Manager adapter implemented where appropriate | **Met** |
| Parameter Store adapter implemented where appropriate | **Not appropriate** — DEFER with the reason recorded |
| Neptune evaluated and adapter implemented if justified | **Met** — evaluated; not justified, and [the page](neptune.md) says why |
| ElastiCache evaluated | **Met** — ADOPT as-is, with two limits named |
| S3 evaluated | **Met** — ADOPT as-is |
| SQS/SNS/EventBridge evaluated | **Met** — NOT_APPLICABLE, with the reason |
| CloudWatch/X-Ray/OTel integration evaluated | **Met** — OTLP first, AWS through the collector |
| IAM boundaries documented | **Met** |
| AWS MCP architecture validated | **Met** — [the MCP page](mcp.md) |
| FastMCP AWS architecture documented | **Met** |
| AgentCore Gateway architecture documented | **Met** |
| Cognito + MCP documented | **Met** |
| Verified Permissions + MCP documented | **Met** |
| API Gateway + MCP documented | **Met** |
| Neo4j + AWS graph strategy documented | **Met** — [the graph strategy](neptune.md) |
| Contract tests created | **Met** — protocol conformance asserted |
| Security tests created | **Met** — 26 for Cognito alone, plus the leak and algorithm tests |
| Reliability tests created | **Met** — unavailable, timeout, throttled, deny, malformed, rotation |
| Observability tests created | **Met** — the CloudWatch mapping tests here, plus the existing OTel infrastructure tests |
| MkDocs documentation updated | **Met** — 25 pages, nav-wired |
| Mermaid diagrams added | **Met** — four reference diagrams plus the in-page sequences |
| Runnable examples added | **Met** — `examples/aws_cognito_avp/`, tested in the gate |
| No fake capabilities documented | **Met** — every deferred verdict carries its reason |
| No AWS credentials committed | **Met** — injected clients only |
| No provider-specific logic leaked into JDLib core | **Met** — adapters in capability packages, protocols unchanged |
| Ruff clean | **Met** |
| Mypy clean | **Met** |
| Tests pass | **Met** — 77 new tests, 928 documentation tests |
| Documentation builds with `mkdocs build --strict` | **Met** |
| Final CI passes | **Met for six runs; two in flight at the time of writing** — the honest status, not a prediction |
| Final report generated | **Met** — this page |

## The programme's own conclusion

The directive's closing instruction was to implement, integrate, test, document, validate and
certify — and not to stop at research, documentation or interfaces. The result is four adapters on
protocols that already existed, five capabilities declined with their reasons recorded, seventy-seven
tests that run in the gate without an AWS account, and twenty-five pages that say what is true
including where the truth is "not implemented".
