"""The container `require(...)` reads from `app.state`, and the lines that are the example's.

`JdlibContainer` is what the library's guard looks up per request: a session factory, a unit of work
factory, and the enforcer. Two of the three are the library's own shapes; the enforcer is
`CerbosEnforcer`, the adapter in `authorization.py` that lets the guard ask Cerbos.

Both factories read the **ambient context** rather than taking one, because the library's
dependencies are context-free by design (`uow_factory()` is called with no arguments, inside a
request, after the middleware has resolved the tenant). Outside a request they raise
`MissingTenantContext` -- which is correct: a session that exists without a tenant is exactly the
state the tenant plane must not have.

The session is the **tenant plane's**, bound to one tenant at connect time, and the unit of work
carries the **write fence**, built once and shared. That ordering matters: the guard opens a unit of
work before the handler runs, so a write to a suspended tenant is refused before the handler is
called, not after it has done half its work. A fence constructed per request would also open a
control-plane pool per request, which is how a lab passes and a deployment falls over.
"""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession

from examples.enterprise.app.dataplane import TenantPlane
from examples.enterprise.app.security.authorization import CerbosEnforcer
from jdlib import UnitOfWork, current_tenant
from jdlib.integrations.fastapi import JdlibContainer
from jdlib.persistence.models import WriteFence


def build_container(
    *,
    plane: TenantPlane,
    fence: WriteFence,
    enforcer: CerbosEnforcer,
) -> JdlibContainer:
    """The collaborators the guard and the routes read from `app.state`."""

    def session_factory() -> AsyncSession:
        return plane.session_factory_for(current_tenant())()

    def uow_factory() -> UnitOfWork:
        context = current_tenant()
        return UnitOfWork(plane.session_factory_for(context), context, fence=fence)

    return JdlibContainer(
        session_factory=session_factory,
        uow_factory=uow_factory,
        enforcer=enforcer,  # type: ignore[arg-type]  # the adapter satisfies the guard's port
    )
