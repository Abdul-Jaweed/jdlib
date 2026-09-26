"""Verified Permissions adapter tests (AWS directive §6, §36, §38).

Two things are under test: the neutral query maps to a well-formed `IsAuthorized` request, and
nothing in the failure space can produce an allow. The transport is injected, so no AWS account and
no network are involved; the live path is NOT RUN and no test claims otherwise.
"""

import asyncio
import uuid
from collections.abc import Mapping
from datetime import timedelta
from typing import Any, cast

import pytest

from jdlib.security.authz.decision import AuthorizationDecision, AuthorizationQuery
from jdlib.security.authz.interfaces import PolicyDecisionPoint
from jdlib.security.authz.verified_permissions import (
    AvpThrottlingError,
    VerifiedPermissionsConfig,
    VerifiedPermissionsPDP,
)
from jdlib.security.errors import SecurityConfigurationError
from tests.support.context_fakes import FrozenClock

TENANT = uuid.UUID("11111111-1111-1111-1111-111111111111")


def _query(**overrides: Any) -> AuthorizationQuery:
    base: dict[str, Any] = {
        "principal_id": "alice",
        "tenant_id": TENANT,
        "resource_kind": "Document",
        "resource_id": "doc-1",
        "actions": ("Document:read",),
        "roles": frozenset({"editor"}),
    }
    base.update(overrides)
    return AuthorizationQuery(**base)


def _config(**overrides: Any) -> VerifiedPermissionsConfig:
    base: dict[str, Any] = {"policy_store_id": "ps-1", "region": "eu-west-1"}
    base.update(overrides)
    return VerifiedPermissionsConfig(**base)


class _Transport:
    """A transport that records the call and returns (or raises) what the test says."""

    def __init__(
        self,
        response: Mapping[str, object] | None = None,
        *,
        raises: BaseException | None = None,
        delay: float = 0.0,
    ) -> None:
        self.response = response
        self.raises = raises
        self.delay = delay
        self.calls: list[tuple[str, Mapping[str, object], Mapping[str, str]]] = []

    async def __call__(
        self, url: str, payload: Mapping[str, object], headers: Mapping[str, str]
    ) -> Mapping[str, object]:
        self.calls.append((url, payload, headers))
        if self.delay:
            await asyncio.sleep(self.delay)
        if self.raises is not None:
            raise self.raises
        return self.response if self.response is not None else {"decision": "DENY"}


def _pdp(transport: _Transport, **overrides: Any) -> VerifiedPermissionsPDP:
    return VerifiedPermissionsPDP(
        config=_config(**overrides), transport=transport, clock=FrozenClock()
    )


# -- the protocol and the config --------------------------------------------------


def test_it_satisfies_the_same_protocol_cerbos_satisfies() -> None:
    assert isinstance(_pdp(_Transport()), PolicyDecisionPoint)


@pytest.mark.parametrize(
    "overrides",
    [
        {"policy_store_id": ""},
        {"timeout": timedelta(0)},
        {"timeout": timedelta(seconds=-1)},
        {"endpoint": "http://localhost:9"},
        {"principal_entity_type": ""},
        {"action_entity_type": ""},
    ],
)
def test_configuration_that_cannot_be_safe_is_rejected(overrides: dict[str, Any]) -> None:
    with pytest.raises(SecurityConfigurationError):
        _config(**overrides)


def test_an_endpoint_needs_either_region_or_endpoint() -> None:
    config = VerifiedPermissionsConfig(policy_store_id="ps-1")
    with pytest.raises(SecurityConfigurationError, match="region or endpoint"):
        config.resolved_endpoint()
    assert (
        VerifiedPermissionsConfig(
            policy_store_id="ps-1", endpoint="https://vp.example.com/"
        ).resolved_endpoint()
        == "https://vp.example.com"
    )


# -- the mapping ------------------------------------------------------------------


async def test_the_query_becomes_a_well_formed_is_authorized_request() -> None:
    transport = _Transport({"decision": "ALLOW", "determiningPolicies": [{"policyId": "p-1"}]})
    decision = await _pdp(transport).decide(_query(request_id="req-9"))
    url, payload, headers = transport.calls[0]
    assert url == "https://verifiedpermissions.eu-west-1.amazonaws.com"
    assert headers == {}
    assert payload["policyStoreId"] == "ps-1"
    principal = cast("Mapping[str, Any]", payload["principal"])
    assert principal["entityType"] == "User" and principal["entityId"] == "alice"
    assert cast("Mapping[str, Any]", principal["attributes"])["roles"] == ["editor"]
    assert payload["action"] == {"actionType": "Document", "actionId": "read"}
    resource = cast("Mapping[str, Any]", payload["resource"])
    assert resource["entityType"] == "Document" and resource["entityId"] == "doc-1"
    assert cast("Mapping[str, Any]", resource["attributes"])["tenantId"] == str(TENANT)
    context = cast("Mapping[str, Any]", payload["context"])
    context_map = cast("Mapping[str, Any]", context["contextMap"])
    assert context_map["tenantId"] == str(TENANT)
    assert context_map["requestId"] == "req-9"
    assert decision.allowed and decision.policy_id == "p-1"


async def test_an_action_without_a_separator_stays_whole() -> None:
    transport = _Transport({"decision": "DENY"})
    await _pdp(transport).decide(_query(actions=("read",)))
    assert transport.calls[0][1]["action"] == {"actionType": "Action", "actionId": "read"}



async def test_an_allow_is_an_allow_even_alongside_policy_errors() -> None:
    # AVP skips erroring policies and decides from the rest, so an ALLOW with errors is still an
    # ALLOW; the errors are not hidden, they are just not treated as a decision.
    transport = _Transport({"decision": "ALLOW", "errors": [{"errorDescription": "boom"}]})
    decision = await _pdp(transport).decide(_query())
    assert decision.allowed and not decision.degraded


async def test_a_deny_carries_the_denied_actions() -> None:
    decision = await _pdp(_Transport({"decision": "DENY"})).decide(_query())
    assert not decision.allowed and decision.denied_actions == ("Document:read",)


# -- nothing in the failure space may allow ---------------------------------------


@pytest.mark.parametrize(
    "response",
    [
        {},
        {"decision": "MAYBE"},
        {"decision": None},
        {"decision": 1},
        {"errors": []},
    ],
)
async def test_an_unusable_response_is_degraded_and_denied(response: dict[str, object]) -> None:
    decision = await _pdp(_Transport(response)).decide(_query())
    assert not decision.allowed
    assert decision.degraded
    assert decision.reason in {"engine_response_invalid", "engine_result_unknown"}


async def test_an_unreachable_engine_is_degraded_and_denied() -> None:
    decision = await _pdp(_Transport(raises=RuntimeError("connection refused"))).decide(_query())
    assert not decision.allowed and decision.degraded
    assert decision.reason == "engine_unavailable"


async def test_a_throttled_engine_is_degraded_and_says_so() -> None:
    decision = await _pdp(_Transport(raises=AvpThrottlingError("slow down"))).decide(_query())
    assert not decision.allowed and decision.degraded
    assert decision.reason == "engine_throttled"


async def test_a_slow_engine_times_out_into_a_denial() -> None:
    transport = _Transport({"decision": "ALLOW"}, delay=0.5)
    decision = await _pdp(transport, timeout=timedelta(seconds=0.01)).decide(_query())
    assert not decision.allowed and decision.degraded
    assert decision.reason == "engine_unavailable"


async def test_cancellation_propagates_rather_than_becoming_a_denial() -> None:
    # CancelledError is a BaseException, so a cancelled request is not silently converted into an
    # authorization answer the caller never asked for.
    transport = _Transport({"decision": "ALLOW"}, delay=5.0)
    task = asyncio.ensure_future(_pdp(transport).decide(_query()))
    await asyncio.sleep(0.01)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


async def test_a_degraded_decision_can_never_be_allowed() -> None:
    # The invariant is enforced by the decision type itself, not by this adapter's discipline.
    for reason in ("engine_unavailable", "engine_throttled", "engine_response_invalid"):
        decision = AuthorizationDecision.unavailable(reason=reason, decided_at=FrozenClock().now())
        assert not decision.allowed and decision.degraded
