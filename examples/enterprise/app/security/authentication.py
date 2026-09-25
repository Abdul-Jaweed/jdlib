"""Authentication: the library's composite authenticator, wired to this application.

There is nothing to implement here, and that is the point: `build_authenticator` returns the
library's own chain -- OIDC when `JDLIB_OIDC__*` is configured, API keys always -- and the
application passes `authenticate` to `install(...)` as its principal provider. Its third
collaborator is the *platform* audit (authentication attempts are platform events), which is a
different writer from the security-event sink beside it. A second
implementation would be a second place for a token check to drift.
"""

from __future__ import annotations

from collections.abc import Callable

from sqlalchemy.ext.asyncio import AsyncSession

from jdlib.authn.wiring import build_authenticator
from jdlib.config import TenancyConfig
from jdlib.control.audit import PlatformAudit
from jdlib.tenancy.middleware import PrincipalProvider


def build_principal_provider(
    *,
    config: TenancyConfig,
    session_factory: Callable[[], AsyncSession],
    audit: PlatformAudit,
) -> PrincipalProvider:
    """The library's authenticator chain, as the middleware's principal provider."""
    return build_authenticator(config, session_factory, audit).authenticate
