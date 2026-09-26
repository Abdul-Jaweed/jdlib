# Rate limiting and admission

Two different things, often confused:

| | Where it lives | What it protects |
|---|---|---|
| **rate limiting** | the deployment's edge (the gateway, or an ingress) | the service from a caller |
| **admission** | `jdlib.reliability.concurrency.ConcurrencyGate` | a dependency from the service |

JDLib implements admission. Rate limiting belongs to the edge, and the library's gateway adapter
reads what the edge asserts rather than re-implementing it.

## The gate

```python
from jdlib.reliability.concurrency import ConcurrencyGate, ConcurrencyLimitError

gate = ConcurrencyGate(limit=...)

async with gate:              # raises ConcurrencyLimitError when the limit is reached
    ...
```

* **The limit is per process.** A fleet's effective limit is the limit times the number of workers,
  which is why the number belongs to the deployment's capacity planning and not to a default.
* **A refusal is visible.** `ConcurrencyLimitError` becomes the canonical envelope (a `429`-class
  refusal) and a metric, so an operator can see admission pressure rather than infer it from latency.
* **It is not a queue.** The gate refuses rather than buffering; a queue in front of a struggling
  dependency is a memory leak with a nicer name.

## Where it is tested

`tests/unit/` for the gate's semantics under concurrency, and the examples for the envelope a refusal
produces.
