# Test your integration

Four layers, and the discipline that makes them worth having.

## The layers

| Layer | Needs | What belongs there |
|---|---|---|
| unit | nothing | behaviour in isolation: the guard, the catalog, the envelope, the policies |
| integration | a real dependency | the same behaviour against the real thing, in a container or the lab |
| security | a real dependency | the composed chain: denial as non-execution, tenant isolation, degraded dependencies |
| e2e | the whole application | the walkthrough a deployment performs, over the real surfaces |

Select them **by directory**, not by marker: most suites in this repository are unmarked, and a
marker-based selection runs a subset while looking like it ran everything.

## The skip rule

A test that needs a live dependency skips when the environment does not point at one:

```python
pytestmark = pytest.mark.skipif(
    not os.environ.get("MY_APP_LIVE_DSN"), reason="needs a live PostgreSQL (MY_APP_LIVE_DSN)"
)
```

Never a fake in the layer that is supposed to be live: a suite that reports green against a double
while claiming to be the integration layer is worse than a skipped test, because the skip is visible
and the green is not.

## The three tests worth copying

1. **A denial is non-execution.** Assert the handler or tool body did not run, using a side effect it
   would have written — and keep an allowing control in the same test so a guard that refuses
   everything cannot pass it.
2. **The tenant comes from the credential.** Send a token or header that claims a different tenant and
   assert the response carries the credential's tenant. This is the assertion that catches a second
   source for the tenant.
3. **A degraded dependency is a refusal.** Point the policy engine (or the JWKS) at a dead port and
   assert a refusal, not a pass. An outage that silently becomes a permission is the failure this
   library exists to prevent.

## Running them

```bash
pytest tests/unit -q -W error                     # the fast loop
pytest tests/integration -q                       # against containers or the lab
bash scripts/ci-local.sh                          # the whole gate, including the docs build
```

## What goes wrong

| Symptom | The cause |
|---|---|
| a security test passes with the guard removed | it asserts a status code, not non-execution |
| the integration layer is green but nothing is live | the skip condition is inverted, or a double replaced the dependency |
| tests pass locally and fail in CI | the environment was assumed rather than read from an env var with a documented default |
