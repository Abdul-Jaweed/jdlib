# Retries and budgets

`jdlib.reliability.budget.RetryBudget` is a *shared allowance* for retries, not a per-call attempt
count.

## Why a budget

A per-call retry policy multiplies load on a dependency that is already failing: every caller retries,
and the dependency sees the product of their attempts. A budget is spent once and then refuses, so a
degraded dependency sees a bounded load while it recovers.

```python
from jdlib.reliability.budget import RetryBudget

budget = RetryBudget(capacity=..., window=...)

try:
    budget.spend()          # raises RetryBudgetExhaustedError when the allowance is gone
except RetryBudgetExhaustedError:
    ...                     # fail fast: the dependency is struggling, not flaky
```

## The rules

* **Retry only what is retryable.** A validation failure, a denial and a not-found are not transient;
  retrying them spends the budget on a certain failure.
* **The budget is the outer bound.** The breaker decides *whether* to attempt; the budget decides how
  many attempts the process will make in total; a timeout bounds each one.
* **Exhaustion is a refusal with a name.** `RetryBudgetExhaustedError` is distinguishable from the
  dependency's own error, so an operator can tell "the dependency is down" from "we gave up".

## Where it is tested

`tests/unit/` for the budget's arithmetic and the exhaustion path; the examples' live layers for the
composed behaviour against a real dependency.
