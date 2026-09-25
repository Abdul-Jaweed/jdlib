"""The tenant-scoped routes. Each one declares the permission it needs.

Every route here is behind the library's guard, and the declaration is the whole authorization
story: `require("...")` runs before the handler, against the enforcer in the container, and a denial
is answered as `403` by the envelope -- the handler is never entered.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends

from examples.enterprise.app.api.schemas import TenantSummary, WhoAmI
from jdlib.context import TenantContext
from jdlib.integrations.fastapi import get_context, require

router = APIRouter(tags=["tenant"])


@router.get("/whoami", dependencies=[Depends(require("tenant:read"))])
async def whoami(context: Annotated[TenantContext, Depends(get_context)]) -> WhoAmI:
    """Who the caller is, in the tenant the middleware resolved.

    Everything here comes from the resolved context: the tenant is not a parameter, and the
    principal is the one the authenticator verified -- not a header a caller could set.
    """
    return WhoAmI(
        tenant=context.tenant_slug,
        principal_kind=context.principal.kind.value,
        principal_id=str(context.principal.id),
        scopes=sorted(context.principal.scopes or ()),
        request_id=context.request_id,
        correlation_id=context.correlation_id,
    )


@router.get("/tenants/current", dependencies=[Depends(require("tenant:read"))])
async def current_tenant_summary(
    context: Annotated[TenantContext, Depends(get_context)],
) -> TenantSummary:
    """The tenant this request is scoped to, and how its data is placed."""
    return TenantSummary(slug=context.tenant_slug, strategy=str(context.strategy))
