---
page: authorization
sources:
  - src/jdlib/security/authz
  - docs/jdlib/capabilities/connectors.md
  - docs/jdlib/04-authorization-model.md
---
# Authorization

## Shape

A single enforcement point - `AuthorizationPEP.require` - asks a PDP (`CerbosPDP.decide`) for a
decision on an `AuthorizationQuery`: principal, tenant, resource kind and id, actions, the
caller's roles (read from the control plane) and the resource's attributes.

```python
await built.enforcer.require(query)   # denial -> 403, undecidable -> 503
```

## Decisions and outcomes

| Decision | Outcome |
|---|---|
| allow | request proceeds |
| deny | `AuthorizationError` → 403 |
| degraded (PDP unreachable, malformed answer) | 503 - never an implicit allow |
| role-less principal | 403 before the PDP is asked, because Cerbos will not decide for one |

The distinction between "no" and "I cannot tell" is deliberate and is visible to the caller.

## Resources carry their tenant

The policy's tenant guard compares the principal's tenant with the resource's, so the resource has
to carry one - and it has to be spelled the same way on both sides. The PEP sends the principal's
as `tenantId`, and a resource attribute under any other spelling would deny every request, which
is why the application spells it once, in the dependency that builds the query, rather than in
each route.

## Contracts

The policy engine is reached through a transport, so the PDP implementation under test is the real
one and a suite can pin decisions without a running engine. Cerbos health is
`GET /_cerbos/health`; the reference stack's engine is Cerbos 0.54.0.

## Audit

Every decision is observed: `AUTHZ_ALLOW`, `AUTHZ_DENY`, `AUTHZ_PDP_ERROR`, with the principal,
the tenant, the resource and the action. The audit trail's own access is an event too.
