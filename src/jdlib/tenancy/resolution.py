from __future__ import annotations

import re
import uuid
from collections.abc import Mapping, Sequence
from typing import NamedTuple, Protocol

from jdlib.config import ResolverConfig, ResolverName
from jdlib.context import Principal, PrincipalKind, TenantRef

_SLUG_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{1,62}$")


class RequestInfo(NamedTuple):
    headers: Mapping[str, str]
    query: Mapping[str, str]
    path: str
    host: str
    claims: Mapping[str, object] = {}


class TenantResolver(Protocol):
    async def resolve(
        self, request: RequestInfo, principal: Principal | None
    ) -> TenantRef | None: ...


def _slug_ref(value: str) -> TenantRef | None:
    candidate = value.strip().lower()
    if not candidate:
        return None
    try:
        return TenantRef(id=uuid.UUID(candidate))
    except ValueError:
        pass
    if _SLUG_PATTERN.match(candidate):
        return TenantRef(slug=candidate)
    return None


class JwtClaimResolver:
    def __init__(self, *, claim: str = "tid") -> None:
        self._claim = claim

    async def resolve(self, request: RequestInfo, principal: Principal | None) -> TenantRef | None:
        value = request.claims.get(self._claim)
        if not isinstance(value, str):
            return None
        return _slug_ref(value)


class SubdomainResolver:
    def __init__(self, *, base_domain: str) -> None:
        self._base = base_domain.strip().lower().rstrip(".")

    async def resolve(self, request: RequestInfo, principal: Principal | None) -> TenantRef | None:
        host = request.host.strip().lower().rstrip(".")
        suffix = f".{self._base}"
        if not host.endswith(suffix):
            return None
        label = host[: -len(suffix)]
        if not label or "." in label:
            return None
        return _slug_ref(label)


class PathResolver:
    def __init__(self, *, prefix: str = "/t/") -> None:
        self._prefix = prefix if prefix.endswith("/") else f"{prefix}/"

    async def resolve(self, request: RequestInfo, principal: Principal | None) -> TenantRef | None:
        if not request.path.startswith(self._prefix):
            return None
        remainder = request.path[len(self._prefix):]
        segment = remainder.split("/", 1)[0]
        return _slug_ref(segment)


class HeaderResolver:
    def __init__(self, *, name: str = "X-Tenant-Slug") -> None:
        self._name = name.lower()

    async def resolve(self, request: RequestInfo, principal: Principal | None) -> TenantRef | None:
        value = request.headers.get(self._name)
        if value is None:
            return None
        return _slug_ref(value)


class ApiKeyResolver:
    async def resolve(self, request: RequestInfo, principal: Principal | None) -> TenantRef | None:
        if principal is None or principal.kind is not PrincipalKind.SERVICE_ACCOUNT:
            return None
        if principal.tenant_id is None:
            return None
        return TenantRef(id=principal.tenant_id)


class ResolverChain:
    def __init__(self, resolvers: Sequence[TenantResolver]) -> None:
        self.resolvers = list(resolvers)

    async def resolve(self, request: RequestInfo, principal: Principal | None) -> TenantRef | None:
        for resolver in self.resolvers:
            resolved = await resolver.resolve(request, principal)
            if resolved is not None:
                return resolved
        return None


def build_chain(config: ResolverConfig) -> ResolverChain:
    resolvers: list[TenantResolver] = []
    for name in config.order:
        if name is ResolverName.JWT_CLAIM:
            resolvers.append(JwtClaimResolver(claim=config.jwt_claim))
        elif name is ResolverName.SUBDOMAIN:
            if config.base_domain:
                resolvers.append(SubdomainResolver(base_domain=config.base_domain))
        elif name is ResolverName.PATH:
            resolvers.append(PathResolver(prefix=config.path_prefix))
        elif name is ResolverName.HEADER:
            resolvers.append(HeaderResolver(name=config.header_name))
        elif name is ResolverName.API_KEY:
            resolvers.append(ApiKeyResolver())
    return ResolverChain(resolvers)
