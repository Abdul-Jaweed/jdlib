from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

import sqlalchemy as sa
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from sqlalchemy.ext.asyncio import AsyncSession

from jdlib.authn.base import bearer_token, record_authn_failure
from jdlib.config import ApiKeyConfig
from jdlib.context import Clock, Principal, PrincipalKind, SystemClock
from jdlib.control.audit import PlatformAudit
from jdlib.control.models import ApiKey, ServiceAccount
from jdlib.control.session import ControlPlaneSession
from jdlib.errors import InvalidToken
from jdlib.tenancy.resolution import RequestInfo

_HASHER = PasswordHasher()


@dataclass(frozen=True, slots=True)
class ParsedApiKey:
    key_prefix: str
    secret: str


def parse_api_key(token: str) -> ParsedApiKey:
    parts = token.split(".")
    if len(parts) != 3 or not all(parts):
        raise InvalidToken("malformed api key")
    return ParsedApiKey(key_prefix=f"{parts[0]}.{parts[1]}", secret=parts[2])


def hash_api_key_secret(secret: str) -> str:
    return _HASHER.hash(secret)


def verify_api_key_secret(secret: str, stored_hash: str) -> bool:
    try:
        return _HASHER.verify(stored_hash, secret)
    except (VerificationError, InvalidHashError):
        return False


class ApiKeyAuthenticator:
    def __init__(
        self,
        *,
        session_factory: Callable[[], AsyncSession],
        audit: PlatformAudit,
        config: ApiKeyConfig | None = None,
        clock: Clock | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._audit = audit
        self._prefix = (config or ApiKeyConfig()).prefix
        self._clock = clock or SystemClock()

    async def authenticate(self, request: RequestInfo) -> Principal | None:
        token = bearer_token(request)
        if token is None or token.split(".", 1)[0] != self._prefix:
            return None
        try:
            parsed = parse_api_key(token)
            principal = await self._resolve(parsed)
        except Exception as exc:
            await record_authn_failure(self._audit, type(exc).__name__)
            return None
        if principal is None:
            await record_authn_failure(self._audit, "invalid_api_key")
        return principal

    async def _resolve(self, parsed: ParsedApiKey) -> Principal | None:
        async with ControlPlaneSession(self._session_factory()) as session:
            key = (
                await session.execute(
                    sa.select(ApiKey).where(ApiKey.key_prefix == parsed.key_prefix)
                )
            ).scalar_one_or_none()
            if key is None or key.status != "active":
                return None
            if key.expires_at is not None and key.expires_at <= self._clock.now():
                return None
            if not verify_api_key_secret(parsed.secret, key.key_hash):
                return None
            account = await session.get(
                ServiceAccount, {"tenant_id": key.tenant_id, "id": key.service_account_id}
            )
            if account is None or account.status != "active":
                return None
            scopes = frozenset(key.scopes) if key.scopes is not None else None
            principal = Principal(
                kind=PrincipalKind.SERVICE_ACCOUNT,
                id=account.id,
                tenant_id=key.tenant_id,
                api_key_id=key.id,
                scopes=scopes,
            )
            key.last_used_at = self._clock.now()
            await session.commit()
            return principal
