"""The Cognito + Verified Permissions chain, exercised end to end without AWS.

A locally generated RSA key pair stands in for the user pool and an injected transport stands in
for Verified Permissions, so the whole chain -- token, principal, query, decision, HTTP status --
runs in the gate. The live path is NOT RUN: no AWS account is involved.
"""

from collections.abc import Mapping
from datetime import timedelta
from typing import Any, cast
from uuid import UUID

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from examples.aws_cognito_avp.composition import (
    GROUPS_CLAIM,
    build_cognito_avp_stack,
    http_status_for,
)
from jdlib.errors import AuthenticationError, InvalidToken
from jdlib.security.authn.cognito import CognitoConfig
from jdlib.security.authz.verified_permissions import (
    AvpThrottlingError,
    VerifiedPermissionsConfig,
)
from tests.support.context_fakes import FrozenClock

ISSUER = "https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_POOL1"
CLIENT_ID = "7exampleclientid"
TENANT = UUID("11111111-1111-1111-1111-111111111111")


def _pool() -> tuple[Any, dict[str, list[dict[str, object]]]]:
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = pyjwt.algorithms.RSAAlgorithm.to_jwk(private.public_key(), as_dict=True)
    jwk["kid"] = "id-token-key"
    jwk["alg"] = "RS256"
    jwk["use"] = "sig"
    return private, {"keys": [jwk]}


class _Fetcher:
    def __init__(self, jwks: dict[str, list[dict[str, object]]]) -> None:
        self.jwks = jwks

    async def __call__(self, url: str) -> dict[str, list[dict[str, object]]]:
        return self.jwks


class _Avp:
    def __init__(
        self,
        response: dict[str, object] | None = None,
        *,
        raises: BaseException | None = None,
    ) -> None:
        self.response = response or {"decision": "DENY"}
        self.raises = raises
        self.calls: list[dict[str, object]] = []

    async def __call__(
        self, url: str, payload: Mapping[str, object], headers: Mapping[str, str]
    ) -> dict[str, object]:
        # Mapping, not dict: the transport protocol is contravariant in its arguments, so a callable
        # that demands a dict would not satisfy it.
        self.calls.append(dict(payload))
        if self.raises is not None:
            raise self.raises
        return self.response


def _token(private: Any, clock: FrozenClock, **overrides: Any) -> str:
    now = clock.now()
    claims: dict[str, Any] = {
        "iss": ISSUER,
        "aud": CLIENT_ID,
        "sub": "user-1",
        "token_use": "id",
        "iat": now,
        "exp": now + timedelta(minutes=5),
        GROUPS_CLAIM: ["editor"],
    }
    claims.update(overrides)
    return pyjwt.encode(claims, private, algorithm="RS256", headers={"kid": "id-token-key"})


def _private_token(private: Any) -> str:
    """A token for the default key, minted against a frozen clock."""
    return _token(private, FrozenClock())


def _stack(avp: _Avp, jwks: dict[str, list[dict[str, object]]]) -> Any:
    clock = FrozenClock()
    return build_cognito_avp_stack(
        cognito=CognitoConfig(issuer=ISSUER, audience=CLIENT_ID),
        avp=VerifiedPermissionsConfig(policy_store_id="ps-1", region="eu-west-1"),
        fetch=_Fetcher(jwks),
        transport=avp,
        clock=clock,
    )


async def test_an_allowed_decision_comes_back_with_200() -> None:
    private, jwks = _pool()
    clock = FrozenClock()
    avp = _Avp({"decision": "ALLOW", "determiningPolicies": [{"policyId": "p-1"}]})
    decision = await _stack(avp, jwks).authorize(
        _token(private, clock),
        tenant_id=TENANT,
        resource_kind="Document",
        resource_id="doc-1",
        actions=("Document:read",),
    )
    assert decision.allowed and http_status_for(decision) == 200
    # The group claim became a role, and the tenant travelled with the query.
    principal = cast("dict[str, Any]", avp.calls[0]["principal"])
    assert cast("dict[str, Any]", principal["attributes"])["roles"] == ["editor"]
    resource = cast("dict[str, Any]", avp.calls[0]["resource"])
    assert cast("dict[str, Any]", resource["attributes"])["tenantId"] == str(TENANT)


async def test_a_denial_comes_back_with_403() -> None:
    private, jwks = _pool()
    avp = _Avp({"decision": "DENY"})
    decision = await _stack(avp, jwks).authorize(
        _private_token(private),
        tenant_id=TENANT,
        resource_kind="Document",
        resource_id="doc-1",
        actions=("Document:read",),
    )
    assert not decision.allowed and http_status_for(decision) == 403


async def test_an_unreachable_decision_point_comes_back_with_503_not_403() -> None:
    # The distinction an operator needs: "we could not decide" is not "you may not".
    private, jwks = _pool()
    avp = _Avp(raises=AvpThrottlingError("slow down"))
    decision = await _stack(avp, jwks).authorize(
        _private_token(private),
        tenant_id=TENANT,
        resource_kind="Document",
        resource_id="doc-1",
        actions=("Document:read",),
    )
    assert not decision.allowed and decision.degraded
    assert http_status_for(decision) == 503


async def test_an_invalid_token_never_reaches_the_decision_point() -> None:
    private, jwks = _pool()
    avp = _Avp({"decision": "ALLOW"})
    stranger = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with pytest.raises(AuthenticationError):
        await _stack(avp, jwks).authorize(
            _private_token(stranger),
            tenant_id=TENANT,
            resource_kind="Document",
            resource_id="doc-1",
            actions=("Document:read",),
        )
    assert avp.calls == []


async def test_a_token_of_the_wrong_type_is_refused() -> None:
    private, jwks = _pool()
    clock = FrozenClock()
    with pytest.raises(InvalidToken, match="token_use"):
        await _stack(_Avp(), jwks).authenticate(_token(private, clock, token_use="access"))
