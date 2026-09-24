from __future__ import annotations

import inspect
from typing import Any

REQUIRED_METHODS = ("open", "close", "health", "execute")


def assert_connector_contract(candidate: Any) -> list[str]:
    """Check a connector against the contract, returning every problem rather than the first.

    The point is that a connector can be validated at startup instead of discovered to be
    wrong in production, and that async discipline is checked by inspection: a synchronous
    implementation returning a value looks fine until it blocks the event loop under load,
    so it is refused here rather than reasoned about later.
    """
    problems: list[str] = []
    for name in REQUIRED_METHODS:
        method = getattr(candidate, name, None)
        if method is None:
            problems.append(f"{name} is missing")
            continue
        if not inspect.iscoroutinefunction(method):
            problems.append(f"{name} must be async, and is not")
    try:
        capabilities = candidate.capabilities
    except Exception as exc:
        problems.append(f"capabilities could not be read: {type(exc).__name__}")
        return problems
    if capabilities is None or not getattr(capabilities, "name", "").strip():
        problems.append("capabilities must declare a name")
    return problems
