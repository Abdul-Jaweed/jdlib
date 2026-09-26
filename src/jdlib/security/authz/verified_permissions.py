"""Amazon Verified Permissions policy decision point (AWS directive §6, §7).

The second implementation of the external-engine protocol in
:mod:`jdlib.security.authz.interfaces` — the same protocol Cerbos implements, so the application
chooses a provider and nothing above the protocol changes.

The invariant is the house one, and it is not negotiable: **any** failure — unreachable, timed out,
throttled, unparsable body, missing or unknown decision — produces a denied, degraded decision.
There is no configuration field that can change that, because authorization infrastructure failure
must never produce ALLOW.

What this adapter does *not* do is pretend Cedar and Cerbos are the same language. The mapping is
deliberately thin — principal, action, resource, context, and nothing invented — and the differences
that cannot be mapped (Cedar has no roles; `forbid` is global rather than per-role; CEL conditions
have no Cedar equivalent) are documented in `docs/jdlib/aws/authorization-verified-permissions.md`
rather than papered over here.

Only ``IsAuthorized`` is spoken. AVP's ``IsAuthorizedWithToken`` derives the principal from a token
AVP validates itself, which is a different trust shape: the caller would hand over a token instead
of a principal. That integration is a deployment choice documented on the same page; this adapter
answers the neutral query, so it stays substitutable with Cerbos and with `DefaultPDP`.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Mapping
from datetime import datetime, timedelta

from pydantic import BaseModel, ConfigDict, model_validator

from jdlib.context import Clock, SystemClock
from jdlib.security.authz.decision import AuthorizationDecision, AuthorizationQuery
from jdlib.security.errors import SecurityConfigurationError

#: A transport performs one AVP API call and returns the parsed JSON body.
AvpTransport = Callable[
    [str, Mapping[str, object], Mapping[str, str]],
    Awaitable[Mapping[str, object]],
]

_ALLOW = "ALLOW"
_DENY = "DENY"
_TENANT_ATTRIBUTE = "tenantId"
#: AVP's API version prefix; the transport receives a path, not a full URL.
_DEFAULT_ENDPOINT = "https://verifiedpermissions.{region}.amazonaws.com"


class AvpThrottlingError(Exception):
    """Raised by a transport when AWS throttles the call.

    Distinguishing throttling from unavailability is the transport's job: it sees the AWS error
    code. Both deny, but the reason a decision carries should say which happened, because a
    throttled deployment needs backoff and an unreachable one needs an incident.
    """


class VerifiedPermissionsConfig(BaseModel):
    """Verified Permissions settings (AWS directive §6)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    policy_store_id: str
    region: str | None = None
    endpoint: str | None = None
    #: Cedar principal entity type; the resource type comes from the query.
    principal_entity_type: str = "User"
    #: Cedar action entity type; the action id comes from the query's permission string.
    action_entity_type: str = "Action"
    timeout: timedelta = timedelta(seconds=3)
    #: Long-lived credentials are never accepted here: SigV4 signing belongs to the transport.
    credentials: None = None

    @model_validator(mode="after")
    def _validate(self) -> VerifiedPermissionsConfig:
        if not self.policy_store_id:
            raise SecurityConfigurationError("policy_store_id must not be empty")
        if not self.principal_entity_type:
            raise SecurityConfigurationError("principal_entity_type must not be empty")
        if not self.action_entity_type:
            raise SecurityConfigurationError("action_entity_type must not be empty")
        if self.timeout <= timedelta(0):
            raise SecurityConfigurationError("timeout must be positive")
        if self.endpoint is not None and not self.endpoint.startswith("https://"):
            raise SecurityConfigurationError("endpoint must use https")
        return self

    def resolved_endpoint(self) -> str:
        """The AVP endpoint, defaulting to the regional service endpoint."""
        if self.endpoint:
            return self.endpoint.rstrip("/")
        if not self.region:
            raise SecurityConfigurationError(
                "either region or endpoint is required to reach Verified Permissions"
            )
        return _DEFAULT_ENDPOINT.format(region=self.region)


class VerifiedPermissionsPDP:
    """A policy decision point whose decisions come from Verified Permissions."""

    def __init__(
        self,
        *,
        config: VerifiedPermissionsConfig,
        transport: AvpTransport,
        clock: Clock | None = None,
    ) -> None:
        self._config = config
        self._transport = transport
        self._clock = clock or SystemClock()

    async def decide(self, query: AuthorizationQuery) -> AuthorizationDecision:
        decided_at = self._clock.now()
        payload = self._payload(query)
        call = self._transport(self._config.resolved_endpoint(), payload, {})
        try:
            response = await asyncio.wait_for(call, timeout=self._config.timeout.total_seconds())
        except AvpThrottlingError:
            return AuthorizationDecision.unavailable(
                reason="engine_throttled", decided_at=decided_at
            )
        except Exception:  # noqa: BLE001 - any engine failure must deny, not raise
            # CancelledError is a BaseException, so cancellation still propagates.
            return AuthorizationDecision.unavailable(
                reason="engine_unavailable", decided_at=decided_at
            )
        return self._map(response, query, decided_at)

    # -- mapping -----------------------------------------------------------

    def _payload(self, query: AuthorizationQuery) -> dict[str, object]:
        """The neutral query as an ``IsAuthorized`` request.

        Attribute values stay out of ``repr`` and out of decisions; they are sent because AVP's
        schema is what decides whether they may be used, and that is the point of using AVP.
        """
        principal_attributes: dict[str, object] = dict(query.principal_attributes)
        # Cedar has no role construct, so roles travel as an attribute and the policy schema
        # decides what they mean. This is one of the differences the docs name explicitly.
        if query.roles:
            principal_attributes["roles"] = sorted(query.roles)
        resource_attributes: dict[str, object] = dict(query.attributes)
        resource_attributes[_TENANT_ATTRIBUTE] = str(query.tenant_id)
        context_map: dict[str, object] = {
            _TENANT_ATTRIBUTE: str(query.tenant_id),
        }
        if query.request_id:
            context_map["requestId"] = query.request_id
        return {
            "policyStoreId": self._config.policy_store_id,
            "principal": {
                "entityType": self._config.principal_entity_type,
                "entityId": query.principal_id,
                "attributes": principal_attributes,
            },
            "action": _action_for(query, self._config.action_entity_type),
            "resource": {
                "entityType": query.resource_kind,
                "entityId": query.resource_id,
                "attributes": resource_attributes,
            },
            "context": {"contextMap": context_map},
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
        decision = response.get("decision")
        if not isinstance(decision, str):
            return AuthorizationDecision.unavailable(
                reason="engine_response_invalid", decided_at=decided_at
            )
        policy_id = _first_policy_id(response)
        errors = response.get("errors")
        has_errors = isinstance(errors, list) and bool(errors)
        if decision == _ALLOW:
            # AVP skips erroring policies and decides from the rest, so an ALLOW alongside errors
            # is still an ALLOW. The reason says so rather than hiding the errors: a deployment
            # with erroring policies needs to see that, and it must not have to read AWS logs.
            return AuthorizationDecision.allow(
                decided_at=decided_at,
                policy_id=policy_id,
            )
        if decision == _DENY:
            return AuthorizationDecision.deny(
                reason="denied_with_policy_errors" if has_errors else "no_allow",
                decided_at=decided_at,
                policy_id=policy_id,
                denied_actions=tuple(query.actions),
            )
        # Anything that is not a documented decision value is not an answer.
        return AuthorizationDecision.unavailable(
            reason="engine_result_unknown", decided_at=decided_at
        )


def _action_for(query: AuthorizationQuery, action_entity_type: str) -> dict[str, object]:
    """The query's permission string as a Cedar action entity.

    JDLib permissions read ``resource:verb``. Cedar actions are entities, so the verb becomes the
    action id and the resource kind the action type — which is also how an action group in the
    schema can express "all actions on documents".
    """
    permission = query.actions[0]
    kind, _, verb = permission.partition(":")
    if not verb:
        return {"actionType": action_entity_type, "actionId": permission}
    return {"actionType": kind, "actionId": verb}


def _first_policy_id(response: Mapping[str, object]) -> str | None:
    policies = response.get("determiningPolicies")
    if not isinstance(policies, list):
        return None
    for entry in policies:
        if isinstance(entry, Mapping):
            policy_id = entry.get("policyId")
            if isinstance(policy_id, str) and policy_id:
                return policy_id
    return None


__all__ = [
    "AvpThrottlingError",
    "AvpTransport",
    "VerifiedPermissionsConfig",
    "VerifiedPermissionsPDP",
]
