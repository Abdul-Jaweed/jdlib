---
guide: authorization
authority: docs/jdlib/authorization.md
modules:
  - src/jdlib/security/authz/pep.py
  - src/jdlib/security/authz/decision.py
  - src/jdlib/security/authz/cerbos.py
  - src/jdlib/authz/scopes.py
  - src/jdlib/integrations/fastapi.py
exports:
  - AuthorizationPEP
  - AuthorizationQuery
  - AuthorizationDecision
  - CerbosPDP
  - CerbosConfig
  - CerbosTransport
  - Effect
  - ScopeRef
  - require
example:
  - examples/enterprise/app/security/authorization.py
  - examples/enterprise/app/api/resources.py
test_files:
  - tests/unit/security/test_authz_pep.py
  - tests/unit/security/test_authz_decision.py
---
# Authorization

> **Design authority:** [`docs/jdlib/authorization.md`](../authorization.md) — this guide is the developer-facing
> shape of that page, not a second authority for it. Where the two disagree, the authority page and
> the code win.

## What it is

A declared permission per operation, asked of a policy engine before the handler runs, with the answer mapped to either execution or the canonical refusal.

## Why it exists

A check inside a handler is a check someone can forget to call, and one that runs after the work has started is not a check at all. Declaring the permission on the route makes the requirement part of the route's shape.

## When to use it

Every operation that reads or writes tenant data, and every operation whose *effect* matters (suspending a tenant, exporting data). Ask for the smallest capability the operation needs.

## When not to use it

For probes, static content, and anything whose answer is the same for every caller. Do not invent a permission per route where one capability describes the operation.

## How it works

`require("resource:write")` returns a FastAPI dependency: it builds an `AuthorizationQuery` (principal, tenant, resource, action, roles), puts it to the `AuthorizationPEP`, and raises `PermissionDenied` on a denial -- before the handler is entered. `AuthorizationPEP.require` also refuses a *degraded* answer, so an unreachable engine fails closed.

## Architecture

`security/authz/decision.py` is the query and its decision; `pep.py` is where policy is asked; `cerbos.py` is the transport to a real engine; `authz/scopes.py` names the targets. The application supplies the engine and the role directory, and nothing else.

## Example

`examples/enterprise/app/api/resources.py` declares `require("resource:read")` / `require("resource:write")` on each route and re-checks nothing in the handler; the live tests get their answers from a real Cerbos with the policies in `examples/enterprise/config/cerbos/policies/`.

## Security

Denials fail closed, and the refusal is one canonical envelope naming the permission and no policy internals. The decision is recorded (`security.AUTHZ_DENY.DENIED` in the example's trail) so a denial can be audited after the fact. A refusal raises before the handler, so a denied operation executes nothing -- which the example measures at the row.

## Reliability

The engine is a dependency: an unreachable or degraded engine answers `AuthorizationUnavailable` (503), never an allow. Roles come from the caller's own directory lookup, so a role cannot be claimed by a header.

## Observability

Each decision is a `SecuritySpan` with the action, the target and the outcome; its ids join it to the request that caused it.

## Audit

Decisions are `SecurityAuditEvent`s: an allow and a denial both land in the trail with the action that was asked about. `DecisionObserver` lets a deployment react to denials without reading the database.

## Configuration

The engine's endpoint and client configuration are application settings; the policies live with the deployment (`config/cerbos/policies/`) and are compiled and tested by the engine's own suite.

## Testing

The library tests the PEP and the decision model; the example tests the policy set with the engine's own tests and drives allow/deny/cross-tenant cases live, including the control that the same caller *with* the role is allowed.

## Common mistakes

Checking inside the handler; checking after the write; treating a degraded engine as an allow; re-mapping the refusal into a second error shape; granting a role from a request field.

## Production checklist

Keep the engine's availability in `/readyz` (a degraded engine must not read as ready), version the policies with the deployment, run the policy tests in the gate, and watch denials as a signal -- a sudden rise is an attack or a broken policy.
