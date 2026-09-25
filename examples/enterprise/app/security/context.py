"""The security context: the library's factory, wired to the control plane and to a real record.

`ContextFactory` is where a verified principal, a resolved tenant, its entitlements and (for the
privileged path) an operator grant become the `TenantContext` every layer below reads. The library
supplies the factory and the adapters that answer it from the control plane; the one collaborator
it deliberately leaves to the application is the operator directory, because *who is an operator,
and for what* is a deployment's own policy.
"""

from __future__ import annotations

from collections.abc import Callable

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession

from jdlib.authn.wiring import (
    EntitlementAdapter,
    PrincipalDirectoryAdapter,
    TenantDirectoryAdapter,
)
from jdlib.authz.reader import ControlAccessReader
from jdlib.config import TenancyConfig
from jdlib.context import ContextFactory, Principal
from jdlib.control.audit import PlatformAudit, PrivilegeAuditAdapter
from jdlib.control.enums import OperatorLevel
from jdlib.control.models import PlatformOperator
from jdlib.control.registry import TenantRegistry

#: What each operator level may ask for, in this deployment's vocabulary.
#:
#: The library asks a yes/no question -- `OperatorAuthorizer.authorize(principal, capability)` --
#: and never guesses at the capability's name: the vocabulary belongs to the application, so it is
#: declared here, next to the levels the control plane's own constraint allows.
_OPERATOR_CAPABILITIES: dict[OperatorLevel, frozenset[str]] = {
    OperatorLevel.SUPPORT: frozenset({"tenant:read", "audit:read"}),
    OperatorLevel.OPERATOR: frozenset({"tenant:read", "audit:read", "tenant:suspend"}),
    OperatorLevel.ADMIN: frozenset(
        {"tenant:read", "audit:read", "tenant:suspend", "tenant:archive", "data:export"}
    ),
}


class OperatorDirectory:
    """Who is a platform operator, answered from the control plane's own record.

    A grant is the row: there is no expiry column in the model, so revocation is deletion, and the
    check is a read of the table rather than a claim from a token. An unknown level grants nothing
    -- the mapping is an allow-list, and a level this deployment has not defined is not a licence.
    """

    def __init__(self, *, session_factory: Callable[[], AsyncSession]) -> None:
        self._sessions = session_factory

    async def authorize(self, principal: Principal, capability: str) -> bool:
        async with self._sessions() as session:
            level = (
                await session.execute(
                    sa.select(PlatformOperator.level).where(
                        PlatformOperator.user_id == principal.id
                    )
                )
            ).scalar_one_or_none()
        if level is None:
            return False
        try:
            known = OperatorLevel(level)
        except ValueError:
            return False
        return capability in _OPERATOR_CAPABILITIES.get(known, frozenset())


def build_context_factory(
    *,
    config: TenancyConfig,
    reader: ControlAccessReader,
    registry: TenantRegistry,
    audit: PlatformAudit,
    session_factory: Callable[[], AsyncSession],
) -> ContextFactory:
    """The library's context factory, with every collaborator answered by the control plane."""
    return ContextFactory(
        config=config.context,
        principals=PrincipalDirectoryAdapter(reader),
        tenants=TenantDirectoryAdapter(registry),
        servability=registry,
        entitlements=EntitlementAdapter(reader),
        operators=OperatorDirectory(session_factory=session_factory),
        audit=PrivilegeAuditAdapter(audit),
    )
