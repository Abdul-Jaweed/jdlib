from __future__ import annotations

from typing import Protocol

from jdlib.context import Principal
from jdlib.control.audit import PlatformAudit
from jdlib.tenancy.resolution import RequestInfo


class Authenticator(Protocol):
    async def authenticate(self, request: RequestInfo) -> Principal | None: ...


async def record_authn_failure(audit: PlatformAudit, reason: str) -> None:
    await audit.record(
        action="authn.failed",
        tenant_id=None,
        actor_id=None,
        metadata={"reason": reason},
    )


def bearer_token(request: RequestInfo) -> str | None:
    header = request.headers.get("authorization")
    if header is None:
        return None
    parts = header.split(None, 1)
    if len(parts) != 2:
        return None
    scheme, value = parts
    if scheme.lower() != "bearer" or not value.strip():
        return None
    return value.strip()
