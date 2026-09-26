# Add a connector

A connector is a data source behind a contract, with its capabilities declared rather than assumed.

## 1. Implement the contract

```python
from jdlib.data.connector import ...
from jdlib.data.capabilities import ...


class MyConnector:
    """Declares what it can do, then does only that."""
```

`jdlib.data.capabilities` is the point: a connector that cannot do something says so, and the policy
in `jdlib.data.policy` refuses an operation the connector does not claim. A capability that is not
declared is not attempted — which is the difference between a refusal and an error at the wrong layer.

## 2. Register it

```python
from jdlib.data.registry import ...

registry.register("mysql", MyConnector(...))
```

## 3. State what is verified

PostgreSQL is the one connector with an implementation in this repository, and the other four engines
are deferred by decision rather than forgotten — the [roadmap](../jdlib/successor/05-roadmap.md)
records it. If you add one, the honest move is to say which parts are exercised by a live suite and
which are not; the [coverage matrix](../jdlib/examples/coverage-matrix.md) is where that is recorded
here, and its MySQL row is the example of a seam that exists without a vendor behind it.

## 4. Test it

| Test | What it proves |
|---|---|
| the declared capabilities are the ones implemented | the declaration is not decoration |
| an undeclared operation is refused | the policy is enforced, not advisory |
| a live round trip | against a real instance, or skipped with a reason |

## What goes wrong

| Symptom | The cause |
|---|---|
| an operation fails deep in the driver | the capability was not declared, so nothing refused it earlier |
| the connector works but the breaker never opens | the connector's failures are not surfacing as the error types the policy classifies |
| a suite reports the connector as verified | it was tested against a double — say so in the coverage matrix instead |
