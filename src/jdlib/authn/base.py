from __future__ import annotations

from typing import Protocol

from jdlib.context import Principal
from jdlib.tenancy.resolution import RequestInfo


class Authenticator(Protocol):
    async def authenticate(self, request: RequestInfo) -> Principal | None: ...


def bearer_token(request: RequestInfo) -> str | None:
    header = request.headers.get("authorization")
    if header is None:
        return None
    scheme, _, value = header.partition(" ")
    if scheme.lower() != "bearer" or not value:
        return None
    return value
