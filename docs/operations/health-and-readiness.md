# Health and readiness

Two probes, two questions, and a rule: a probe must not depend on anything the process does not need
to answer it.

| Probe | The question | What it checks |
|---|---|---|
| `/healthz` | is this process serving? | nothing but itself |
| `/readyz` | can this process do useful work? | `SELECT 1` against the control plane |

```python
@app.get("/healthz")
async def healthz() -> dict[str, str]:
    """Liveness: the process is serving. No credentials, no dependency checks."""
    return {"status": "ok"}


@app.get("/readyz")
async def readyz() -> dict[str, str]:
    """Readiness: SELECT 1 against the control plane. An unreachable database is 503."""
    await control_sessions.execute(text("SELECT 1"))
    return {"status": "ready"}
```

## Why liveness must not check dependencies

A liveness probe that needs a token fails during an identity-provider outage, and the orchestrator
restarts a healthy process for it. The restart does not fix the identity provider, and it removes the
capacity that would have served the requests that still work.

## The failure path

A readiness failure answers `503 DEPENDENCY_UNAVAILABLE` through the library's own envelope, so the
route carries no readiness-specific handling and the probe sees the same error shape a client does.
The minimal example asserts exactly this, including the case where its database is down.

## During a shutdown

Readiness flips **before** the drain begins, so the balancer stops sending new work while the process
is still able to finish what it accepted. A probe that stays ready until the process exits guarantees
dropped requests on every deploy.
