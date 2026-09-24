"""Phase 3: CerbosPDP adapter contract (directive §15, §16, §17).

The adapter is the only place that knows Cerbos' wire format. It is driven here
through an injected transport, so the contract under test is exact: the request
body Cerbos receives, the mapping of its response into the neutral decision
model, and — most importantly — every failure path.

Authorization infrastructure failure must never produce ALLOW (directive §16).
Each of these must therefore yield a denied, degraded decision:

* connection failure / Cerbos unavailable,
* timeout, including a transport that never returns,
* non-2xx responses (5xx, 401, 404),
* a body that is not JSON, or JSON without results,
* a result carrying an error status,
* an unknown/unspecified effect token,
* a response whose action results are incomplete.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from jdlib.security.authz.decision import AuthorizationDecision, AuthorizationQuery
from jdlib.security.authz.interfaces import PolicyDecisionPoint
from jdlib.security.errors import SecurityConfigurationError

CERBOS_URL = "http://localhost:3592"
TENANT_ID = uuid.UUID("11111111-2222-3333-4444-555555555555")
NOW = datetime(2026, 6, 1, 12, 0, tzinfo=UTC)
AUTHORIZATION_HEADER = "Authorization"
SECRET_ATTRIBUTE = "confidential-classification-value"


class FixedClock:
    def now(self) -> datetime:
        return NOW


class Transport:
    """Records requests and returns a scripted response."""

    def __init__(self, response: object = None, *, error: BaseException | None = None) -> None:
        self.calls: list[tuple[str, Mapping[str, object], Mapping[str, str]]] = []
        self.response = response
        self.error = error
        self.hang = False

    async def __call__(
        self, url: str, payload: Mapping[str, object], headers: Mapping[str, str]
    ) -> Mapping[str, object]:
        self.calls.append((url, payload, headers))
        if self.hang:
            await asyncio.sleep(30)
        if self.error is not None:
            raise self.error
        assert self.response is not None
        return self.response  # type: ignore[return-value]

    @property
    def payload(self) -> Mapping[str, object]:
        return self.calls[-1][1]

    @property
    def url(self) -> str:
        return self.calls[-1][0]


def _config(**overrides: object):
    from jdlib.security.authz.cerbos import CerbosConfig

    values: dict[str, object] = {
        "endpoint": CERBOS_URL,
        "timeout": timedelta(seconds=2),
    }
    values.update(overrides)
    return CerbosConfig(**values)  # type: ignore[arg-type]


def _pdp(transport: Transport, **overrides: object):
    from jdlib.security.authz.cerbos import CerbosPDP

    return CerbosPDP(
        config=_config(**overrides),
        transport=transport,
        clock=FixedClock(),
    )


def _query(*, actions: tuple[str, ...] = ("read",)) -> AuthorizationQuery:
    return AuthorizationQuery(
        principal_id="user-1",
        tenant_id=TENANT_ID,
        resource_kind="document",
        resource_id="doc-42",
        actions=actions,
        roles=frozenset({"editor"}),
        attributes={"classification": SECRET_ATTRIBUTE},
    )


def _response(
    actions: Mapping[str, str],
    *,
    policy_id: str = "document",
    policy_version: str = "default",
    include_meta: bool = True,
) -> Mapping[str, object]:
    result: dict[str, object] = {
        "resource": {"id": "doc-42", "kind": "document"},
        "actions": dict(actions),
    }
    if include_meta:
        result["meta"] = {
            "actions": {
                action: {"matchedPolicy": policy_id, "matchedScope": policy_version}
                for action in actions
            },
            "effectiveDerivedRoles": ["editor"],
        }
    return {"requestId": "req-1", "results": [result]}


# --- configuration -----------------------------------------------------------


def test_config_is_schema_locked_against_fail_open() -> None:
    # There must be no field that could be set to allow on engine failure.
    with pytest.raises(ValidationError):
        _config(fail_open=True)
    assert not hasattr(_config(), "fail_open")
    assert not hasattr(_config(), "allow_on_error")


def test_config_requires_secure_endpoint() -> None:
    for endpoint in ("http://cerbos.example.com", "cerbos:3592", "ftp://cerbos"):
        with pytest.raises(SecurityConfigurationError):
            _config(endpoint=endpoint)
    assert _config(endpoint="https://cerbos.internal").endpoint == "https://cerbos.internal"
    assert _config(endpoint="http://localhost:3592").endpoint == "http://localhost:3592"


def test_config_requires_positive_timeout() -> None:
    with pytest.raises(SecurityConfigurationError):
        _config(timeout=timedelta(0))


def test_adapter_satisfies_the_pdp_port() -> None:
    assert isinstance(_pdp(Transport(_response({"read": "EFFECT_ALLOW"}))), PolicyDecisionPoint)


def test_repr_hides_config_secrets_and_endpoint_credentials() -> None:
    transport = Transport(_response({"read": "EFFECT_ALLOW"}))
    text = repr(_pdp(transport))
    assert SECRET_ATTRIBUTE not in text


# --- request mapping ---------------------------------------------------------


async def test_request_is_a_cerbos_check_resources_call() -> None:
    transport = Transport(_response({"read": "EFFECT_ALLOW"}))
    await _pdp(transport).decide(_query())
    assert transport.url == f"{CERBOS_URL}/api/check/resources"
    payload = transport.payload
    assert payload["includeMeta"] is True
    principal = payload["principal"]
    resources = payload["resources"]
    assert isinstance(principal, Mapping) and isinstance(resources, list)
    entry = resources[0]
    assert isinstance(entry, Mapping)
    resource = entry["resource"]
    assert isinstance(resource, Mapping)
    assert principal["id"] == "user-1"
    assert principal["roles"] == ["editor"]
    assert principal["attr"]["tenantId"] == str(TENANT_ID)
    assert resource["kind"] == "document"
    assert resource["id"] == "doc-42"
    assert resource["attr"]["classification"] == SECRET_ATTRIBUTE
    assert entry["actions"] == ["read"]


async def test_request_carries_a_request_id_when_the_query_has_one() -> None:
    transport = Transport(_response({"read": "EFFECT_ALLOW"}))
    query = AuthorizationQuery(
        principal_id="user-1",
        tenant_id=TENANT_ID,
        resource_kind="document",
        resource_id="doc-42",
        actions=("read",),
        request_id="req-abc",
    )
    await _pdp(transport).decide(query)
    assert transport.payload["requestId"] == "req-abc"


async def test_request_never_carries_tokens_or_credentials() -> None:
    transport = Transport(_response({"read": "EFFECT_ALLOW"}))
    await _pdp(transport).decide(_query())
    _, payload, headers = transport.calls[-1]
    serialized = json.dumps(payload)
    for forbidden in ("access_token", "id_token", "client_secret", "bearer ", "private_key"):
        assert forbidden not in serialized.lower()
    assert AUTHORIZATION_HEADER.lower() not in {k.lower() for k in headers}


async def test_all_requested_actions_are_sent() -> None:
    transport = Transport(_response({"read": "EFFECT_ALLOW", "write": "EFFECT_ALLOW"}))
    await _pdp(transport).decide(_query(actions=("read", "write")))
    resources = transport.payload["resources"]
    assert isinstance(resources, list)
    entry = resources[0]
    assert isinstance(entry, Mapping)
    assert entry["actions"] == ["read", "write"]


# --- response mapping --------------------------------------------------------


async def test_allow_maps_to_an_allowed_decision_with_policy_metadata() -> None:
    transport = Transport(_response({"read": "EFFECT_ALLOW"}))
    decision = await _pdp(transport).decide(_query())
    assert decision.allowed is True
    assert decision.degraded is False
    assert decision.policy_id == "document"
    assert decision.policy_version == "default"
    assert decision.decided_at == NOW


async def test_deny_maps_to_a_denied_decision() -> None:
    transport = Transport(_response({"read": "EFFECT_DENY"}))
    decision = await _pdp(transport).decide(_query())
    assert decision.allowed is False
    assert decision.denied_actions == ("read",)
    assert decision.policy_id == "document"


async def test_all_actions_must_be_allowed() -> None:
    transport = Transport(_response({"read": "EFFECT_ALLOW", "delete": "EFFECT_DENY"}))
    decision = await _pdp(transport).decide(_query(actions=("read", "delete")))
    assert decision.allowed is False
    assert decision.denied_actions == ("delete",)


async def test_missing_action_result_counts_as_denied() -> None:
    transport = Transport(_response({"read": "EFFECT_ALLOW"}))
    decision = await _pdp(transport).decide(_query(actions=("read", "write")))
    assert decision.allowed is False
    assert decision.denied_actions == ("write",)


async def test_unknown_effect_token_is_denied() -> None:
    transport = Transport(_response({"read": "EFFECT_UNSPECIFIED"}))
    decision = await _pdp(transport).decide(_query())
    assert decision.allowed is False


async def test_deny_without_meta_still_denies() -> None:
    transport = Transport(_response({"read": "EFFECT_DENY"}, include_meta=False))
    decision = await _pdp(transport).decide(_query())
    assert decision.allowed is False
    assert decision.policy_id is None


# --- fail closed: infrastructure failure never allows ------------------------


@pytest.mark.parametrize(
    "failure",
    [
        ConnectionError("cerbos is not running"),
        OSError("network unreachable"),
        TimeoutError("timed out"),
        ValueError("malformed json"),
    ],
)
async def test_transport_failures_are_denied_and_degraded(failure: BaseException) -> None:
    transport = Transport(error=failure)
    decision = await _pdp(transport).decide(_query())
    assert decision.allowed is False
    assert decision.degraded is True
    assert decision.policy_id is None


async def test_a_hanging_transport_times_out_and_denies() -> None:
    transport = Transport(_response({"read": "EFFECT_ALLOW"}))
    transport.hang = True
    started = asyncio.get_running_loop().time()
    decision = await _pdp(transport, timeout=timedelta(milliseconds=100)).decide(_query())
    elapsed = asyncio.get_running_loop().time() - started
    assert decision.allowed is False
    assert decision.degraded is True
    assert elapsed < 2.0


@pytest.mark.parametrize(
    "response",
    [
        {"results": []},
        {},
        {
            "results": [
                {
                    "resource": {"id": "doc-42"},
                    "status": {"code": 2, "message": "policy error"},
                }
            ]
        },
        {"results": [{"resource": {"id": "doc-42"}, "actions": {}, "meta": {}}]},
        {"results": [{"resource": {"id": "other-resource"}, "actions": {"read": "EFFECT_ALLOW"}}]},
    ],
)
async def test_malformed_or_incomplete_responses_deny(response: Mapping[str, object]) -> None:
    transport = Transport(response)
    decision = await _pdp(transport).decide(_query())
    assert decision.allowed is False
    assert decision.degraded is True


async def test_a_denied_decision_never_becomes_allowed_by_missing_meta() -> None:
    transport = Transport(_response({"read": "EFFECT_DENY"}, include_meta=False))
    decision = await _pdp(transport).decide(_query())
    assert isinstance(decision, AuthorizationDecision)
    assert decision.allowed is False
