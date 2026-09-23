from __future__ import annotations

from collections.abc import Sequence

from jdlib.authn.base import Authenticator
from jdlib.context import Principal
from jdlib.tenancy.resolution import RequestInfo


class CompositeAuthenticator:
    def __init__(self, authenticators: Sequence[Authenticator]) -> None:
        self._authenticators = list(authenticators)

    async def authenticate(self, request: RequestInfo) -> Principal | None:
        for authenticator in self._authenticators:
            principal = await authenticator.authenticate(request)
            if principal is not None:
                return principal
        return None
