"""Wire a Cognito authenticator to a Verified Permissions decision point.

Everything here is composition: no new security logic, no new protocol. The two adapters exist
independently and this module is the seam between them, which is the point of the example -- an
application using both does not need a third abstraction, only a decision about what a token's
claims mean.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from uuid import UUID

from jdlib.context import Clock
from jdlib.errors import InvalidToken
from jdlib.security.authn.cognito import (
    CognitoConfig,
    JwksFetch,
    build_cognito_token_validator,
    unverified_claims,
    validate_cognito_token,
)
from jdlib.security.authn.jwt import JwtTokenValidator
from jdlib.security.authz.decision import AuthorizationDecision, AuthorizationQuery
from jdlib.security.authz.pep import AuthorizationPEP
from jdlib.security.authz.verified_permissions import (
    AvpTransport,
    VerifiedPermissionsConfig,
    VerifiedPermissionsPDP,
)
from jdlib.security.interfaces import ValidatedToken

#: Cognito puts group membership in this claim; the Cedar schema decides what a group may do.
GROUPS_CLAIM = "cognito:groups"


@dataclass(frozen=True, slots=True)
class CognitoAvpStack:
    """The two adapters and the PEP, wired but not yet used."""

    cognito: CognitoConfig
    avp: VerifiedPermissionsConfig
    validator: JwtTokenValidator
    pep: AuthorizationPEP

    async def authenticate(self, token: str) -> ValidatedToken:
        """Validate a Cognito token and enforce the token type the deployment expects."""
        return await validate_cognito_token(self.validator, self.cognito, token)

    def roles_from(self, token: str) -> frozenset[str]:
        """Read group membership from a token that has already been validated.

        Called after `authenticate`, never before: reading a claim from an unverified token is how
        a caller ends up trusting a group a user does not belong to.
        """
        groups = unverified_claims(token).get(GROUPS_CLAIM)
        if not isinstance(groups, list):
            return frozenset()
        return frozenset(str(group) for group in groups)

    async def authorize(
        self,
        token: str,
        *,
        tenant_id: UUID,
        resource_kind: str,
        resource_id: str,
        actions: tuple[str, ...],
        attributes: Mapping[str, object] | None = None,
    ) -> AuthorizationDecision:
        """Authenticate, then ask Verified Permissions. Returns the decision without raising.

        `AuthorizationPEP.require` does the same and raises typed errors inside a request; this
        example uses `check` so it can show the mapping explicitly, which is also what a caller that
        wants to render its own refusal does.
        """
        validated = await self.authenticate(token)
        query = AuthorizationQuery(
            principal_id=validated.subject,
            tenant_id=tenant_id,
            resource_kind=resource_kind,
            resource_id=resource_id,
            actions=actions,
            roles=self.roles_from(token),
            attributes=attributes or {},
        )
        return await self.pep.check(query)


def build_cognito_avp_stack(
    *,
    cognito: CognitoConfig,
    avp: VerifiedPermissionsConfig,
    fetch: JwksFetch,
    transport: AvpTransport,
    clock: Clock | None = None,
) -> CognitoAvpStack:
    """Compose the stack. A deployment supplies a real JWKS fetcher and a SigV4 AVP transport."""
    validator = build_cognito_token_validator(cognito, fetch=fetch, clock=clock)
    pdp = VerifiedPermissionsPDP(config=avp, transport=transport, clock=clock)
    return CognitoAvpStack(
        cognito=cognito,
        avp=avp,
        validator=validator,
        pep=AuthorizationPEP(pdp=pdp),
    )


def http_status_for(decision: AuthorizationDecision) -> int:
    """How an application should answer.

    503 for a degraded decision, not 403: "we could not decide" is not "you may not", and an
    operator needs to see the difference. This is the mapping `AuthorizationPEP.require` applies by
    raising `AuthorizationUnavailable` rather than `PermissionDenied`.
    """
    if decision.allowed:
        return 200
    return 503 if decision.degraded else 403


__all__ = ["GROUPS_CLAIM", "CognitoAvpStack", "build_cognito_avp_stack", "http_status_for"]


# Re-exported so a reader of this example sees the import that matters without hunting for it.
_ = InvalidToken
