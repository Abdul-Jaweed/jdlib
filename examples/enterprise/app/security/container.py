"""The container `require(...)` reads from `app.state`, and the one line that is the example's.

`JdlibContainer` is what the library's guard looks up per request: a session factory, a unit of
work factory, and the enforcer. Two of the three are the library's own shapes; the enforcer is
`CerbosEnforcer`, the adapter in `authorization.py` that lets the guard ask Cerbos.

The session factory here is the **control plane's**, which is not an oversight: the authorization
path reads the control plane (memberships, bindings, role names), and the tenant plane's own engines
arrive with the repositories that use them -- a session the guard opens is a session the guard's
question is answered from.
"""

from __future__ import annotations

from collections.abc import Callable

from sqlalchemy.ext.asyncio import AsyncSession

from examples.enterprise.app.security.authorization import CerbosEnforcer
from jdlib import UnitOfWork, current_tenant
from jdlib.control.registry import RegistryWriteFence
from jdlib.integrations.fastapi import JdlibContainer


def build_container(
    *,
    session_factory: Callable[[], AsyncSession],
    enforcer: CerbosEnforcer,
) -> JdlibContainer:
    """The collaborators the guard and the routes read from `app.state`."""

    def uow_factory() -> UnitOfWork:
        context = current_tenant()
        fence = RegistryWriteFence(session_factory=session_factory)
        return UnitOfWork(session_factory, context, fence=fence)

    return JdlibContainer(
        session_factory=session_factory,
        uow_factory=uow_factory,
        enforcer=enforcer,  # type: ignore[arg-type]  # the adapter satisfies the guard's port
    )
