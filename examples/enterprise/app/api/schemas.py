"""Response models. What leaves the process is declared here, not assembled ad hoc.

None of these carries an internal identifier a caller has no use for: a response is the tenant's
own data and the ids it needs to correlate its request, and nothing else.
"""

from __future__ import annotations

from pydantic import BaseModel


class WhoAmI(BaseModel):
    """The caller's own view of the request: who, in which tenant, under which request."""

    tenant: str
    principal_kind: str
    principal_id: str
    scopes: list[str]
    request_id: str
    correlation_id: str


class TenantSummary(BaseModel):
    """The tenant this request is scoped to."""

    slug: str
    strategy: str
