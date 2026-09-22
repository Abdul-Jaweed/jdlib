from __future__ import annotations

import functools
from collections.abc import Awaitable, Callable
from typing import Any, TypeVar

from jdlib.authz.pdp import Decision, PolicyDecisionPoint
from jdlib.authz.scopes import ScopeRef, Target
from jdlib.context import current_tenant
from jdlib.control.enums import ScopeType
from jdlib.errors import PermissionDenied

F = TypeVar("F", bound=Callable[..., Awaitable[Any]])


def tenant_target() -> ScopeRef:
    return ScopeRef(ScopeType.TENANT, None)


class Enforcer:
    def __init__(self, pdp: PolicyDecisionPoint) -> None:
        self._pdp = pdp

    async def require(self, permission: str, target: Target, *, session: object) -> Decision:
        context = current_tenant()
        decision = await self._pdp.evaluate(
            context.principal, permission, target, context, session=session
        )
        if not decision.allowed:
            raise PermissionDenied(f"{permission}: {decision.reason}")
        return decision


def requires(
    permission: str,
    *,
    enforcer: Enforcer,
    target_factory: Callable[..., Target] | None = None,
) -> Callable[[F], F]:
    def decorate(fn: F) -> F:
        @functools.wraps(fn)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            if target_factory is None:
                target: Target = tenant_target()
            else:
                target = target_factory(*args, **kwargs)
            await enforcer.require(permission, target, session=kwargs.get("session"))
            return await fn(*args, **kwargs)

        return wrapper  # type: ignore[return-value]

    return decorate


async def authorize(
    permission: str, target: Target, *, enforcer: Enforcer, session: object
) -> Decision:
    return await enforcer.require(permission, target, session=session)
