# Cerbos

`jdlib.security.authz.cerbos.CerbosPDP` is the reference decision point: an implementation of the
`DecisionPoint` port that speaks to a Cerbos instance over HTTP. It is the engine the repository's
integration suites run against, and it is not the only one that works.

## The port

| Module | What it is |
|---|---|
| `interfaces` | the decision-point port: the question the library asks |
| `decision` | the answer's shape: allowed, denied, or degraded |
| `pep` | the enforcement point: puts the question, refuses on anything but an allow |
| `cerbos` | `CerbosPDP` and its configuration (`CerbosConfig`) |
| `transports` | the outbound call, with the request identity attached |

## The question, and the three answers

The library asks about a *subject* (the principal from the verified context), a *permission* (the
one the route or tool declared), and a *resource* (with its scope). The answer is one of:

* **allowed** — the operation proceeds;
* **denied** — the operation is refused, and the decision is audited;
* **degraded** — the engine was unreachable, or answered something the library cannot read. A
  degraded answer is treated as a refusal: an outage must not become a permissive default.

The request id the caller sent is carried to the engine, so a decision can be traced back to the
request that asked for it.

## Using your own engine

Implement the port and pass it to the composition — nothing else changes, because the PEP talks to the
port and not to Cerbos:

```python
class MyPDP:  # implements jdlib.security.authz.interfaces.DecisionPoint
    async def decide(self, query: AuthorizationQuery) -> Decision: ...
```

The permission *catalog* (`jdlib.authz.permissions.PermissionCatalog`) names what exists; the engine
decides who may do it. The library never reads your policy.

## Where it is tested

`tests/integration/` and the enterprise example's security layer, both against a live Cerbos: an
allowed call, a denied call (measured as non-execution), and a degraded engine (measured as a
refusal).
