---
page: privileged-access
sources:
  - src/jdlib/context.py
  - src/jdlib/security/audit/events.py
  - tests/unit/test_delegation.py
---
# Privileged access

## One model, several kinds

A privileged operation carries a `PrivilegeContext` whose `kind` says where the authority came
from: `OPERATOR` (a platform operator acting on a tenant, with a justification and a short TTL),
`SYSTEM` (the library acting on its own behalf) and `TEST`. Delegation is **not** a second model -
it is the same descriptor with `kind=DELEGATION` and a `delegation_id` (ADR-3).

## Delegation

`validate_delegation` refuses a delegated privilege unless every condition holds: it is
identified, unused, live, justified, granted for the exact capability requested, scoped to the
target tenant, and its actor is not suspended. It **decides nothing** - there is no third
enforcement point, and anything that is not a delegation passes through untouched, because the
operator path keeps its own semantics.

```python
validate_delegation(privilege, capability="read:events", target_tenant_id=tenant,
                    now=now, seen=used_ids, is_suspended=suspended.is_suspended)
```

Replay is keyed on the delegation identifier and **not** on the capability, so reusing an
identifier for a different capability does not reset the check.

## Evidence and audit

A delegation that is accepted emits `PRIVILEGE_USED`; a refusal emits `AUTHZ_DENY` *before* the
exception is raised, so the record exists even though the caller only sees the refusal. Operator
privileges are short-lived by construction (`operator_ttl` at the context factory) and expire
independently of the request.

## Limits

`seen` and `is_suspended` are injected: the library does not own the record of used delegation
identifiers or the suspension list, and pretends neither.
