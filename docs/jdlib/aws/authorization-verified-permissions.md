---
guide: aws
authority: docs/jdlib/aws/research-sources.md
modules:
  - src/jdlib/security/authz/verified_permissions.py
exports:
  - VerifiedPermissionsConfig
  - VerifiedPermissionsPDP
  - AvpTransport
  - AvpThrottlingError
test_files:
  - tests/unit/test_aws_verified_permissions.py
---

# Authorization with Amazon Verified Permissions

> **Design authority:** [the AWS capability matrix](aws-capability-matrix.md) and
> [the research sources](research-sources.md). This page describes a second implementation of an
> existing protocol — not a second authorization system.

## What it is

A provider adapter for **Amazon Verified Permissions (AVP)**: a managed policy decision service
whose policies are written in Cedar. It sits on the same seam Cerbos sits on:

```text
JDLib PEP
     |
PolicyDecisionPoint            <- the protocol in src/jdlib/authz/pdp.py
     |-- CerbosPDP              <- security/authz/cerbos.py
     |-- DefaultPDP             <- the tenant-plane gates
     `-- VerifiedPermissionsPDP <- planned: security/authz/verified_permissions.py
```

The application chooses the provider; nothing above the protocol changes.

## Why it exists

Because the substitution problem is real: a deployment that is already on AWS may want a managed
decision service rather than a self-hosted PDP. What it must *not* do is create a second
authorization engine — the PEP, the tenant gates, the permission catalog and the audit trail are
the library's, and only the decision call changes hands.

## When to use it

When the deployment runs its authorization decisions in AVP and the application is JDLib. When the
deployment self-hosts Cerbos, use `security/authz/cerbos.py`.

## When not to use it

Do not use it to replace the library's tenant gates. `DefaultPDP` runs the frozen precedence order
(principal active, tenant active, membership active, binding validity, then permission) before any
permission is considered. AVP answers the permission question; it does not know what a JDLib tenant
is.

## Model mapping

| JDLib concept | Cedar / AVP | Notes |
| --- | --- | --- |
| Principal (`Principal`) | `principal` entity, or the principal AVP derives from a token | With `IsAuthorizedWithToken`, AVP builds the principal from the token it validates: ID-token claims become principal attributes, access-token claims become `context.token.*`, and `cognito:groups` becomes parent group entities |
| Action (`permission` string) | `action` entity | JDLib permissions are strings such as `documents:read`; the Cedar schema must declare them, and action groups are AVP's mechanism for grouping |
| Resource (`Target` / `ResourceRef`) | `resource` entity | JDLib resources are tenant-scoped; the entity ID must encode the tenant, or the policy store must, because AVP has no tenancy concept of its own |
| Context (`TenantContext`, request facts) | `context` record | Must be schema-declared to be usable in policies |
| Decision (`Decision(allowed, reason, matched)`) | `Allow` / `Deny` + determining policies | JDLib's `reason` and `matched` are populated from AVP's determining-policy list, so an audit entry can name the policy that decided |

## Differences that an adapter must not paper over

These come from the research, and each one is a place where a naive mapping would be wrong:

* **Roles do not exist in Cedar.** Cerbos has static roles and derived roles computed at evaluation
  time; Cedar has no role construct at all, so roles must become entities in a hierarchy or
  attributes. Derived-role logic has no direct equivalent.
* **"Deny wins" means different things.** In Cerbos, deny overrides allow *per role* for the same
  action, an allow from any one role wins across roles, and principal policies are final overrides.
  In Cedar, any satisfied `forbid` overrides every `permit` globally, with no per-role carve-outs.
* **Conditions are different languages.** Cerbos conditions are CEL with Cerbos extensions; a runtime
  error makes an `ALLOW` rule not match. Cedar conditions are Cedar expressions, and an erroring
  policy is *skipped* with diagnostics. CEL cannot be mechanically translated into Cedar semantics.
* **Who supplies the principal differs.** Cerbos is stateless: the caller supplies the principal's
  ID, roles and attributes on every call, and Cerbos does not validate JWTs. AVP's `WithToken` APIs
  derive the principal from a token AVP itself validates, and reject a mismatched `token_use` or a
  malformed claim. An adapter cannot treat principal attributes as caller-supplied in both backends.
* **Templates and reuse are not shared.** Cerbos uses variables, constants and scoped policies; AVP
  has policy templates constrained so that both principal and resource are bound.
* **Transport, limits and batching differ.** Cerbos is called over gRPC/REST with its own evaluation
  semantics options; AVP is IAM/SigV4 over HTTPS, with 30 requests per batch, one identity source per
  store, and hard byte limits on policies and schemas.
* **Wildcards do not translate.** Cerbos supports action wildcards respecting the `:` delimiter and
  scope-hierarchy walk-up; Cedar actions are entities matched by equality or group membership.

## The Cognito integration, and its caveats

AVP can take a Cognito user pool as an identity source, which is what makes the
[Cognito](authentication-cognito.md) → AVP chain possible without a bespoke token exchange. Four
documented details matter:

* An identity source requires a **same-account** user pool, a principal entity type, a group entity
  type and the client IDs; AVP prefixes entity IDs with the pool ID, so a principal ID is
  `{poolId}|{sub}`.
* With client validation enabled, AVP checks that the token's `client_id` (access token) or `aud`
  (ID token) matches a configured client ID, that the token is not expired, and that `token_use`
  matches the API used.
* **AVP does not check revocation and does not call the IdP.** A revoked token that is otherwise
  valid still decides.
* The documented wizard pattern — API Gateway plus a Lambda authorizer — caches decisions for 120
  seconds, which extends the effective lifetime of a token. Enforcement still happens in the
  application.

## Status

**Implemented** in `security/authz/verified_permissions.py`: `VerifiedPermissionsConfig`,
`VerifiedPermissionsPDP`, and the injected `AvpTransport` seam that keeps AWS credentials and SigV4
signing out of the library. `VerifiedPermissionsPDP` answers the same protocol Cerbos does, and
`tests/unit/test_aws_verified_permissions.py` asserts that conformance with an `isinstance` check
against the runtime-checkable protocol.

Twenty-two tests cover the mapping and the failure space, including the reliability cases the
directive names: engine unavailable, timeout, throttled (`engine_throttled`, distinct from
unavailable, because a throttled deployment needs backoff and an unreachable one needs an incident),
deny, and malformed or unknown responses. Cancellation propagates rather than turning into an
authorization answer nobody asked for. Every degraded decision is denied — and that invariant is
enforced by `AuthorizationDecision` itself, not by this adapter's discipline, so no adapter can
weaken it.

Two honest limits: the transport is injected and no test speaks to AWS, so the live path is
`NOT RUN — AWS credentials unavailable`; and only `IsAuthorized` is spoken, with `IsAuthorizedWithToken`
documented above as the Cognito-native alternative rather than implemented here.

## Limits worth designing around

Authorization request 1 MB; policy 10,000 bytes; schema 100,000 bytes; 30 requests per batch; 100
resources and 99 groups per batch; 200 RPS per policy store for the single-decision APIs and 30 RPS
for the batch APIs, with throttling returned as exceptions that require retry with backoff. A
self-hosted Cerbos PDP has none of these, which is the trade a managed service makes.
