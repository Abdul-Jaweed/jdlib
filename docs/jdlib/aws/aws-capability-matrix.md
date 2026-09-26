---
guide: aws
authority: docs/jdlib/aws/research-sources.md
modules: []
---

# AWS capability matrix

> **What this page is.** The directive's section 4 artifact: every AWS candidate, the JDLib
> abstraction it would have to answer to, and a classification earned from research rather than
> enthusiasm. The classifications are the point — an AWS service being excellent is not a reason to
> write an adapter for it.

**Vocabulary.** `ADOPT` — the existing adapter already speaks it, so the work is documentation.
`ADAPTER` — a real provider-substitution problem, so an adapter is justified.
`OPTIONAL` — a genuine contract exists but the deployment does not require it.
`INFRASTRUCTURE_ONLY` — belongs to deployment or to AWS resource control, never inside JDLib core.
`NOT_APPLICABLE` — JDLib has no such capability to adapt. `DEFER` — feasible but not justified now,
with the reason recorded. `REJECT` — would duplicate or weaken an existing guarantee.

## The matrix

| JDLib capability | JDLib interface | Existing provider | AWS provider | Adapter needed? | Priority | Status |
| --- | --- | --- | --- | --- | --- | --- |
| Authentication | `Authenticator` (`authn/base.py`), `JwtTokenValidator` (`security/authn/jwt.py`) | ZITADEL (`security/authn/zitadel.py`) | Amazon Cognito | **ADAPTER** | P0 | **Implemented** — `security/authn/cognito.py` |
| Application authorization | `PolicyDecisionPoint` (`authz/pdp.py`), `security/authz/interfaces.py` | Cerbos (`security/authz/cerbos.py`), `DefaultPDP` | Amazon Verified Permissions (Cedar) | **ADAPTER** | P0 | **Implemented** — `security/authz/verified_permissions.py` |
| Secret resolution | `SecretProvider.resolve()` (`persistence/secrets.py`) | `MemorySecretProvider`, `EnvSecretProvider` | AWS Secrets Manager | **ADAPTER** | P0 | **Implemented** — `persistence/secrets_manager.py` |
| Application audit sink | `SecurityEventSink` (`security/audit/`) | Postgres-backed sink | CloudWatch Logs | **OPTIONAL** | P2 | Planned — `security/audit/cloudwatch.py` |
| Relational data | `persistence/` + isolation strategies | PostgreSQL (verified against containers and a live lab) | RDS for PostgreSQL, Aurora PostgreSQL | **ADOPT** | P1 | Documented — deployment target, no adapter |
| Cache | `CacheProvider` (`caching/protocol.py`) | Redis (`caching/redis.py`) | ElastiCache (Valkey / Redis OSS) | **ADOPT** | P1 | Documented — same adapter, two caveats |
| Object storage | `ObjectStorageProvider` (`storage/provider.py`) | S3 (`storage/s3.py`, verified against MinIO) | Amazon S3 | **ADOPT** | P1 | Documented — drop `endpoint_url`, keep prefix isolation |
| Observability | `security/tracing.py`, `security/telemetry.py` (OpenTelemetry) | OTel collector | CloudWatch, X-Ray via ADOT | **ADOPT** | P1 | Documented — OTLP first, no AWS calls in core |
| Graph | `GraphClient` / `GraphRunner` (`graph/client.py`) | Neo4j over Bolt | Amazon Neptune (Bolt + openCypher subset) | **DEFER** | P2 | Evaluated — capability differences documented, adapter not justified |
| Configuration | *(none — only `TenancyConfig`, pydantic-settings)* | environment variables | SSM Parameter Store | **DEFER** | P2 | No `ConfigurationProvider` abstraction exists and section 29 forbids inventing one — [the verdict](parameter-store.md) records why, and why it is not smuggled in as a `SecretProvider` |
| Edge gateway | `security/gateway/adapters.py` | Kong, Tyk | Amazon API Gateway | **INFRASTRUCTURE_ONLY** | P1 | **Documented** — [the edge page](api-gateway.md) and [the comparison](gateway-comparison.md); no adapter, because API Gateway signs no identity envelope a backend can verify |
| Messaging | *(none)* | *(none)* | SQS, SNS, EventBridge | **NOT_APPLICABLE** | — | JDLib has no queue or publisher capability to adapt |
| AWS resource authorization | *(none)* | *(none)* | IAM | **INFRASTRUCTURE_ONLY** | P1 | Documented boundary — IAM authorizes AWS resources, not application data |
| MCP gateway | `integrations/mcp/` (FastMCP) | FastMCP, local | Bedrock AgentCore Gateway, API Gateway stages | **OPTIONAL** | P2 | Documented — AgentCore "authenticate only" keeps JDLib the decision point |
| Hosting and edge | *(none)* | *(none)* | ECS/Fargate, ECR, Lambda, CloudFront, WAF | **INFRASTRUCTURE_ONLY** | — | Deployment topology; never a JDLib contract |
| Control-plane audit | *(none)* | *(none)* | AWS CloudTrail | **INFRASTRUCTURE_ONLY** | — | Complements the application audit trail; never replaces it |
| Session and token state | *(none)* | *(none)* | Amazon DynamoDB | **INFRASTRUCTURE_ONLY** | — | Part of the AWS reference MCP architecture's auth service |
| Health and readiness | `/readyz` composition (`integrations/fastapi`) | — | all of the above | **ADOPT** | P2 | Documented — liveness must not depend on every dependency |

## Why the two `ADAPTER` rows are the only ones

**Cognito answers `Authenticator`, and nothing else.** A Cognito user pool is an OIDC identity
provider: it issues RS256 JWTs from a JWKS endpoint, and AWS documents token verification as the
application's job, recommending a JWT library. That maps onto the split JDLib already has — a
provider-neutral `JwtTokenValidator` plus a provider module that supplies discovery, issuer, audience
and the accepted algorithms. The adapter is therefore *configuration and discovery*, not a second
JWT implementation. What Cognito does not provide is recorded on
[the Cognito page](authentication-cognito.md): no policy language, no resource-level decisions, no
tenancy model, and revocation that a JWT check cannot see.

**Verified Permissions answers `PolicyDecisionPoint`, and nothing else.** The PEP → PDP seam already
exists with Cerbos on the other side of it, so this is a second implementation of one protocol, not
a second authorization system. The semantics are not the same and the adapter does not pretend they
are: Cerbos has roles and derived roles, per-role deny-wins, CEL conditions and a caller-supplied
principal; Cedar has no role construct, a global forbid-overrides-permit, skip-on-error evaluation,
and (in the `WithToken` APIs) a principal the service itself derives from a validated token. The
mapping and its limits are on [the Verified Permissions page](authorization-verified-permissions.md).

## Why the `ADOPT` rows need no code

Each of these is an existing adapter that already speaks the protocol the AWS service exposes:

* **RDS and Aurora PostgreSQL** are PostgreSQL: the same driver, the same isolation strategies. The
  deployment facts that change are TLS verification against the RDS CA bundle, IAM database
  authentication (a SigV4 token with a 15-minute lifetime used as the password), and RDS Proxy in
  front of the endpoint.
* **ElastiCache** speaks Redis/Valkey on the wire. Two documented caveats: cluster mode requires a
  cluster-aware client, and IAM authentication requires a SigV4 token provider instead of an AUTH
  password. Neither changes `CacheProvider`.
* **S3** is the service the existing storage adapter was written against — it was verified against
  MinIO precisely because MinIO speaks S3. Real S3 means omitting `endpoint_url` and taking
  credentials from the standard chain. Prefix-based tenant isolation is already the adapter's design.
* **CloudWatch and X-Ray** are reached through OpenTelemetry, not through AWS calls in library code.
  The library emits OTLP through its existing emitter seam and the AWS Distro for OpenTelemetry fans
  out to X-Ray, CloudWatch and any other backend. X-Ray's indexed-annotation versus stored-metadata
  distinction is the one mapping decision, recorded on the observability page.

## Where AWS architecture has evolved

Recorded because the directive asks for it, and because the supplied PDF is a point in time:

* The AWS Solutions reference architecture (Cognito OAuth, revisions reviewed 2025-05-06 and
  2025-09-02) fronts MCP servers with CloudFront, WAF, an ALB, a custom MCP authentication service
  on Fargate, ECR, CloudWatch, Parameter Store, Secrets Manager, Cognito and DynamoDB.
* Amazon Bedrock AgentCore became generally available on 2025-10-13 and supersedes parts of that
  architecture: Gateway replaces the custom MCP auth/aggregation layer, Runtime replaces
  self-managed container hosting, Identity replaces the bespoke token and credential stores, and
  Observability replaces bespoke telemetry plumbing. AWS documents no supersession of CloudFront,
  WAF, CloudWatch, Cognito, Parameter Store or Secrets Manager.
* Current AWS guidance frames three MCP hosting options rather than one — Lambda for lightweight
  stateless tool endpoints, AgentCore for a managed suite with built-in identity, and ECS/Fargate
  where runtime and networking control matter.
* AgentCore Gateway has grown past MCP aggregation to HTTP and inference targets, including API
  Gateway REST API stages, with inbound modes of OAuth/JWT, IAM/SigV4, API key and
  **authenticate-only** — the mode in which the gateway validates identity and deliberately makes no
  authorization decision. That is exactly where JDLib remains the decision point.

## Placement: where the AWS code goes

The directive's section 28 sketch nests everything under `integrations/aws/`, and then says to
inspect the existing architecture first and not to introduce nesting where the repository has a
better pattern. It does. Providers in this repository live **beside their peers, in the capability
package, named for the technology**:

```text
src/jdlib/security/authn/zitadel.py     ->  security/authn/cognito.py
src/jdlib/security/authz/cerbos.py      ->  security/authz/verified_permissions.py
src/jdlib/persistence/secrets.py        ->  persistence/secrets_manager.py
src/jdlib/security/audit/emitters.py    ->  security/audit/cloudwatch.py
```

A monolithic `integrations/aws/` package would put authentication, authorization, secret resolution
and audit behind one directory wall, and would make an AWS deployment structurally different from a
ZITADEL/Cerbos one for no reason a reader could see. `integrations/` keeps its existing meaning in
this repository: application-facing surfaces (CLI, FastAPI, MCP), not provider adapters.

## REJECT rows, recorded

Not every AWS idea is a row above; these were considered and rejected, with the reason:

* **Cognito as an authorization engine** — rejected: groups map to IAM roles for AWS credentials,
  not to application permissions. Application authorization belongs to the PDP.
* **API keys as authentication** — rejected: AWS documents API keys as usage-plan identifiers, not
  credentials, and states plainly not to use them for authentication or authorization.
* **Neptune as a drop-in Neo4j** — rejected: openCypher over Bolt is a subset (no `CALL`, no
  `shortestPath`, no dynamic property access), there is no APOC and no multi-database feature.
* **A second tenancy model** — rejected: tenant identity has exactly one source in this library, and
  a Neptune cluster-per-tenant scheme would be a deployment choice, not a second source of truth.
