from __future__ import annotations

import uuid
from collections.abc import Callable, Mapping

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from jdlib.authn.apikey import ApiKeyAuthenticator
from jdlib.authn.base import Authenticator
from jdlib.authn.composite import CompositeAuthenticator
from jdlib.authn.oidc import ClaimMapper, JwksCache, OidcAuthenticator, TokenVerifier, UserLinker
from jdlib.authz.reader import AccessReader
from jdlib.config import TenancyConfig
from jdlib.context import Principal, TenantRecord, TenantRef
from jdlib.control.audit import PlatformAudit
from jdlib.control.registry import TenantRegistry


async def fetch_jwks(url: str) -> Mapping[str, object]:
    async with httpx.AsyncClient() as client:
        response = await client.get(url)
        response.raise_for_status()
        document: object = response.json()
    if not isinstance(document, Mapping):
        raise ValueError("JWKS document must be a JSON object")
    return document


def build_authenticator(
    config: TenancyConfig,
    session_factory: Callable[[], AsyncSession],
    audit: PlatformAudit,
) -> CompositeAuthenticator:
    authenticators: list[Authenticator] = []
    if config.oidc is not None:
        oidc = config.oidc
        authenticators.append(
            OidcAuthenticator(
                config=oidc,
                cache=JwksCache(
                    url=oidc.resolved_jwks_url(),
                    ttl=oidc.jwks_ttl,
                    fetcher=fetch_jwks,
                ),
                verifier=TokenVerifier(oidc),
                mapper=ClaimMapper(oidc),
                linker=UserLinker(session_factory, oidc),
                audit=audit,
            )
        )
    authenticators.append(
        ApiKeyAuthenticator(
            session_factory=session_factory, audit=audit, config=config.api_keys
        )
    )
    return CompositeAuthenticator(authenticators)


class PrincipalDirectoryAdapter:
    def __init__(self, reader: AccessReader) -> None:
        self._reader = reader

    async def is_active(self, principal: Principal) -> bool:
        return await self._reader.principal_active(principal)


class TenantDirectoryAdapter:
    def __init__(self, registry: TenantRegistry) -> None:
        self._registry = registry

    async def get(self, ref: TenantRef) -> TenantRecord | None:
        return await self._registry.find(ref)


class EntitlementAdapter:
    def __init__(self, reader: AccessReader) -> None:
        self._reader = reader

    async def can_act(self, principal: Principal, tenant_id: uuid.UUID) -> bool:
        if not await self._reader.principal_active(principal):
            return False
        return await self._reader.membership_active(principal, tenant_id)
