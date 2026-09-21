from __future__ import annotations

from collections.abc import Callable
from typing import Any

from jdlib.context import TenantContext
from jdlib.persistence.models import WriteFence, privileged_bypass
from jdlib.persistence.session import RawSqlAuditor, TenantSession


class UnitOfWork:
    def __init__(
        self,
        session_factory: Callable[[], Any],
        context: TenantContext,
        *,
        fence: WriteFence,
        auditor: RawSqlAuditor | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._context = context
        self._fence = fence
        self._auditor = auditor
        self._session: TenantSession | None = None

    async def __aenter__(self) -> TenantSession:
        if not privileged_bypass(self._context):
            await self._fence.assert_writable(self._context.tenant_id)
        raw = self._session_factory()
        self._session = TenantSession(raw, self._context, auditor=self._auditor)
        return self._session

    async def __aexit__(self, exc_type: object, exc: object, tb: object) -> None:
        assert self._session is not None
        try:
            if exc_type is None:
                await self._session.commit()
            else:
                await self._session.rollback()
        finally:
            await self._session.close()
