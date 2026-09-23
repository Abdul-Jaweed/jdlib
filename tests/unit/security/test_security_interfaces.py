"""Phase 1 security core: ports (interfaces) for the adapters.

Spec refs: #5 (ports and adapters), #7 (inbound vs outbound authentication),
#11 (gateway abstraction), #35 (rate limiting interface), #74 (import safety),
#76/#78 (retry and timeout policy are adapter concerns).
"""

from __future__ import annotations

import inspect
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import SecretStr

from jdlib.security.context import TokenMetadata
from jdlib.security.interfaces import (
    GatewayAdapter,
    GatewayIdentity,
    OutboundToken,
    RateLimitDecision,
    RateLimiter,
    TokenProvider,
    TokenValidator,
    ValidatedToken,
)
from jdlib.tenancy.resolution import RequestInfo

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def _request() -> RequestInfo:
    return RequestInfo(headers={}, query={}, path="/", host="api.example.com", claims={})


# --- Token validation (inbound) --------------------------------------------


def test_validated_token_never_carries_the_raw_token() -> None:
    with pytest.raises(TypeError):
        ValidatedToken(  # type: ignore[call-arg]
            subject="user-1",
            metadata=TokenMetadata(),
            raw_token="eyJhbGciOiJIUzI1NiJ9.payload.signature",
        )


def test_validated_token_defaults_to_no_scopes() -> None:
    token = ValidatedToken(subject="user-1", metadata=TokenMetadata())
    assert token.scopes == frozenset()


def test_validator_contract_is_async() -> None:
    assert inspect.iscoroutinefunction(TokenValidator.validate)
    assert inspect.iscoroutinefunction(TokenValidator.ready)


def test_structural_conformance_is_checked_by_runtime_protocol() -> None:
    class Validator:
        async def validate(self, token: str) -> ValidatedToken:
            return ValidatedToken(subject="u", metadata=TokenMetadata())

        async def ready(self) -> bool:
            return True

    class Incomplete:
        async def validate(self, token: str) -> ValidatedToken:
            return ValidatedToken(subject="u", metadata=TokenMetadata())

    assert isinstance(Validator(), TokenValidator)
    assert not isinstance(Incomplete(), TokenValidator)


# --- Token acquisition (outbound) ------------------------------------------


def test_outbound_token_requires_an_expiry() -> None:
    with pytest.raises(TypeError):
        OutboundToken(value=SecretStr("secret"))  # type: ignore[call-arg]


def test_outbound_token_masks_the_secret_everywhere() -> None:
    secret = "eyJhbGciOiJSUzI1NiJ9.outbound.secret"
    token = OutboundToken(value=SecretStr(secret), expires_at=NOW + timedelta(minutes=5))
    for rendered in (repr(token), str(token), f"{token}", repr(token.value), str(token.value)):
        assert secret not in rendered


def test_outbound_token_expiry_is_tracked() -> None:
    token = OutboundToken(value=SecretStr("s"), expires_at=NOW + timedelta(minutes=5))
    assert token.expires_at > NOW
    assert token.token_type == "Bearer"


def test_token_provider_contract_is_async() -> None:
    assert inspect.iscoroutinefunction(TokenProvider.token)
    assert inspect.iscoroutinefunction(TokenProvider.invalidate)


# --- Gateway identity -------------------------------------------------------


def test_gateway_identity_is_immutable_and_time_bounded() -> None:
    identity = GatewayIdentity(
        subject="user-1",
        tenant_slug="acme",
        scopes=frozenset({"documents:read"}),
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=1),
    )
    assert identity.is_valid_at(NOW + timedelta(seconds=30)) is True
    assert identity.is_valid_at(NOW + timedelta(minutes=2)) is False
    assert identity.is_valid_at(NOW - timedelta(seconds=1)) is False
    with pytest.raises(FrozenInstanceError):
        identity.subject = "attacker"  # type: ignore[misc]


def test_gateway_adapter_contract_is_async_and_named() -> None:
    assert inspect.iscoroutinefunction(GatewayAdapter.verify_identity)

    class Adapter:
        name = "test-gateway"

        async def verify_identity(self, request: RequestInfo) -> GatewayIdentity | None:
            return None

    assert isinstance(Adapter(), GatewayAdapter)


# --- Rate limiting ----------------------------------------------------------


def test_rate_limit_decision_fails_closed_by_default() -> None:
    assert RateLimitDecision().allowed is False


def test_rate_limit_denial_can_carry_retry_after() -> None:
    decision = RateLimitDecision.deny(retry_after=timedelta(seconds=30))
    assert decision.allowed is False
    assert decision.retry_after == timedelta(seconds=30)
    assert RateLimitDecision.allow(remaining=5).allowed is True


def test_rate_limiter_contract_is_async() -> None:
    assert inspect.iscoroutinefunction(RateLimiter.check)
