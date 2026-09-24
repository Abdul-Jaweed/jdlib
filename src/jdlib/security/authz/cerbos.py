"""Cerbos policy decision point (directive §15, §16, §17).

The only place that knows Cerbos' wire format. A Cerbos failure of any kind —
unreachable, timed out, 5xx, unparsable body, incomplete result, unknown effect
— produces a **denied, degraded** decision. There is no configuration field
that can change that: authorization infrastructure failure must never produce
ALLOW (directive §16).

Requests are built from the neutral query, and only the principal id, roles,
tenant, resource identity/attributes and the requested actions are sent.
Credentials (tokens, client secrets, private keys) are never part of a policy
request, and response bodies are never echoed into decisions or logs.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import Awaitable, Callable, Mapping
from datetime import datetime, timedelta

from pydantic import BaseModel, ConfigDict, model_validator

from jdlib.context import Clock, SystemClock
from jdlib.security.authz.decision import AuthorizationDecision, AuthorizationQuery
from jdlib.security.errors import SecurityConfigurationError

#: A transport performs one HTTP call and returns the parsed JSON body.
CerbosTransport = Callable[
    [str, Mapping[str, object], Mapping[str, str]],
    Awaitable[Mapping[str, object]],
]

_ALLOW = "EFFECT_ALLOW"
_CHECK_RESOURCES_PATH = "/api/check/resources"
_LOCAL_PREFIXES = ("http://localhost", "http://127.0.0.1")
_TENANT_ATTRIBUTE = "tenantId"


class CerbosConfig(BaseModel):
    """Cerbos coordinates.

    There is deliberately no ``fail_open``/``allow_on_error`` field, and unknown
    fields are rejected, so a deployment cannot be configured to allow requests
    when the engine is unavailable.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    endpoint: str
    timeout: timedelta = timedelta(seconds=2)

    @model_validator(mode="after")
    def _validate(self) -> CerbosConfig:
        if not self.endpoint:
            raise SecurityConfigurationError("cerbos endpoint must not be empty")
        if not self.endpoint.startswith("https://") and not self.endpoint.startswith(
            _LOCAL_PREFIXES
        ):
            raise SecurityConfigurationError(
                "cerbos endpoint must use https (http is allowed only for localhost)"
            )
        if self.timeout <= timedelta(0):
            raise SecurityConfigurationError("cerbos timeout must be positive")
        return self

    def check_resources_url(self) -> str:
        return f"{self.endpoint.rstrip('/')}{_CHECK_RESOURCES_PATH}"


class CerbosPDP:
    """Ask Cerbos for a decision, and never for permission to skip asking."""

    def __init__(
        self,
        *,
        config: CerbosConfig,
        transport: CerbosTransport,
        clock: Clock | None = None,
    ) -> None:
        self._config = config
        self._transport = transport
        self._clock = clock or SystemClock()

    def __repr__(self) -> str:
        return (
            f"CerbosPDP(endpoint={self._config.endpoint!r}, "
            f"timeout={self._config.timeout.total_seconds()}s)"
        )

    # -- port --------------------------------------------------------------

    async def decide(self, query: AuthorizationQuery) -> AuthorizationDecision:
        decided_at = self._clock.now()
        payload = self._payload(query)
        call = self._transport(self._config.check_resources_url(), payload, {})
        try:
            response = await asyncio.wait_for(
                call, timeout=self._config.timeout.total_seconds()
            )
        except Exception:  # noqa: BLE001 - any engine failure must deny, not raise
            # CancelledError is a BaseException, so cancellation still propagates.
            return AuthorizationDecision.unavailable(
                reason="engine_unavailable", decided_at=decided_at
            )
        return self._map(response, query, decided_at)

    # -- mapping -----------------------------------------------------------

    @staticmethod
    def _payload(query: AuthorizationQuery) -> dict[str, object]:
        principal_attributes: dict[str, object] = {_TENANT_ATTRIBUTE: str(query.tenant_id)}
        principal_attributes.update(query.principal_attributes)
        return {
            "requestId": query.request_id or uuid.uuid4().hex,
            "includeMeta": True,
            "principal": {
                "id": query.principal_id,
                "roles": sorted(query.roles),
                "attr": principal_attributes,
            },
            "resources": [
                {
                    "resource": {
                        "kind": query.resource_kind,
                        "id": query.resource_id,
                        "attr": dict(query.attributes),
                    },
                    "actions": list(query.actions),
                }
            ],
        }

    def _map(
        self,
        response: Mapping[str, object],
        query: AuthorizationQuery,
        decided_at: datetime,
    ) -> AuthorizationDecision:
        try:
            return self._map_response(response, query, decided_at)
        except Exception:  # noqa: BLE001 - an unexpected shape is a denial, never a crash
            return AuthorizationDecision.unavailable(
                reason="engine_response_invalid", decided_at=decided_at
            )

    def _map_response(
        self,
        response: Mapping[str, object],
        query: AuthorizationQuery,
        decided_at: datetime,
    ) -> AuthorizationDecision:
        results = response.get("results")
        if not isinstance(results, list) or not results:
            return AuthorizationDecision.unavailable(
                reason="engine_response_invalid", decided_at=decided_at
            )
        result = results[0]
        if not isinstance(result, Mapping):
            return AuthorizationDecision.unavailable(
                reason="engine_response_invalid", decided_at=decided_at
            )
        status = result.get("status")
        if isinstance(status, Mapping) and status:
            # Cerbos reports policy/engine errors here; never allow on those.
            return AuthorizationDecision.unavailable(
                reason="engine_result_error", decided_at=decided_at
            )
        resource = result.get("resource")
        if not isinstance(resource, Mapping) or resource.get("id") != query.resource_id:
            return AuthorizationDecision.unavailable(
                reason="engine_response_mismatch", decided_at=decided_at
            )
        actions = result.get("actions")
        if not isinstance(actions, Mapping) or not actions:
            return AuthorizationDecision.unavailable(
                reason="engine_response_incomplete", decided_at=decided_at
            )
        policy_id, policy_version = self._policy_metadata(result, query)
        denied = tuple(action for action in query.actions if actions.get(action) != _ALLOW)
        if denied:
            return AuthorizationDecision.deny(
                reason="no_allow",
                decided_at=decided_at,
                policy_id=policy_id,
                policy_version=policy_version,
                denied_actions=denied,
            )
        return AuthorizationDecision.allow(
            decided_at=decided_at,
            policy_id=policy_id,
            policy_version=policy_version,
        )

    @staticmethod
    def _policy_metadata(
        result: Mapping[str, object], query: AuthorizationQuery
    ) -> tuple[str | None, str | None]:
        """Capture the policy id and version/revision behind the decision (§17).

        ``matchedPolicy`` is Cerbos' fully qualified policy name
        (``resource.document.vdefault``): it identifies the policy *and* the
        version that produced the effect. ``matchedScope`` is recorded as the
        policy version when a scope matched, and is absent otherwise.
        """
        meta = result.get("meta")
        if not isinstance(meta, Mapping):
            return None, None
        meta_actions = meta.get("actions")
        if not isinstance(meta_actions, Mapping):
            return None, None
        policy_id: str | None = None
        policy_version: str | None = None
        for action in query.actions:
            entry = meta_actions.get(action)
            if not isinstance(entry, Mapping):
                continue
            if policy_id is None and isinstance(entry.get("matchedPolicy"), str):
                policy_id = entry["matchedPolicy"]
            if policy_version is None:
                scope = entry.get("matchedScope")
                if isinstance(scope, str) and scope:
                    policy_version = scope
        return policy_id, policy_version


__all__ = ["CerbosConfig", "CerbosPDP", "CerbosTransport"]
