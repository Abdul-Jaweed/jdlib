---
page: security-model
sources:
  - src/jdlib/security
  - src/jdlib/security/audit
  - src/jdlib/errors.py
  - tests/unit/security
  - docs/security
---
# Security model

## Trust boundaries

1. **The identity provider** is trusted to say who someone is, not what they may do. A verified
   token yields a `Principal`; nothing else is inferred from it.
2. **The policy engine** (Cerbos) decides authorization. The library's PEP observes the decision,
   maps denial to 403 and an undecidable/degraded decision to 503 - never to an allow.
3. **The control plane** is the authority on tenants, memberships and roles. A caller's roles are
   read from it, never taken from a token claim.
4. **The tenant plane** is reachable only through the repository, under RLS bound to the
   application role - a non-superuser, non-`BYPASSRLS` login. If RLS were not enforced, the tests
   would notice, because nothing else filters rows.
5. **Every new capability boundary** refuses before it connects: the query compiler's allow-list
   runs at parse time, storage keys are scoped at construction, a connector will not open for an
   unauthorized context.

## Fail closed

| Situation | Result |
|---|---|
| No security context where one is required | Refusal, never a default tenant |
| IdP unreachable | 503 (`AuthenticationUnavailable`) |
| Policy engine degraded | 503, never an implicit allow |
| Principal with no roles | 403 - a denial, not an unavailable decision |
| Unknown tenant on the privileged surface | 404 |
| A target whose tenant is not the context's | The connector refuses to open |
| A credential pinned to a retired version | `CredentialVersionRetiredError` |

## Audit, telemetry and logs are three different things

The **audit trail** records what happened, with an outcome, in a tenant-scoped or platform table.
**Operational logs** are for operators. **Telemetry** is bounded: span attributes are validated
against an allow-list before they reach an exporter, attributes naming identifiers or credentials
are refused outright, and a collector outage is never allowed to fail the operation it describes.
Audit access is itself an event (`AUDIT_READ_DENIED`, `AUDIT_EXPORTED`).

## Credentials

A secret is addressed by handle and version, resolved through a provider chain, and never
rendered: `ResolvedSecret.__repr__` shows metadata only, `ConnectionConfig` renders without its
target, and the CLI does not print tokens by default. Values must not reach a cache (ADR-2), a
span attribute, an audit record or a log line, and each of those is asserted rather than assumed.

See [`credentials.md`](credentials.md).
