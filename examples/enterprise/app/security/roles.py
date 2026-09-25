"""The roles a principal holds in a tenant -- read from the control plane, per request.

Cerbos decides with roles, and a role is the control plane's record of what a principal was granted
*in this tenant*: not a claim a token carries, and not something the application invents. Reading
the bindings on every request is what makes a revoked role stop working immediately rather than
when the token expires.

The example resolves the names itself because the library exposes the *bindings*
(`ControlAccessReader.bindings_for`) and not the role names: a role's name is the application's
vocabulary, and the library deliberately does not guess it.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession

from jdlib.authz.reader import ControlAccessReader
from jdlib.context import Principal
from jdlib.control.enums import ScopeType
from jdlib.control.models import Role


class RoleDirectory:
    """Role names for a principal in a tenant, from the control plane's own records."""

    def __init__(
        self,
        *,
        reader: ControlAccessReader,
        session_factory: Callable[[], AsyncSession],
    ) -> None:
        self._reader = reader
        self._sessions = session_factory

    async def names_for(self, principal: Principal, tenant_id: uuid.UUID) -> frozenset[str]:
        """The active role names this principal holds in this tenant.

        An empty set is a real answer, not an error: a principal with no roles in a tenant can be
        granted nothing by a role-based policy, and the caller turns that into a denial rather than
        asking the engine a question it cannot answer.
        """
        bindings = await self._reader.bindings_for(
            principal, tenant_id, [(ScopeType.TENANT, None)]
        )
        if not bindings:
            return frozenset()
        role_ids = [binding.role_id for binding in bindings]
        async with self._sessions() as session:
            result = await session.execute(
                sa.select(Role.name).where(
                    Role.tenant_id == tenant_id, Role.id.in_(role_ids)
                )
            )
            return frozenset(result.scalars())
