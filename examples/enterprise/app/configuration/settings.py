"""The enterprise example's own settings -- and nothing the library already owns.

Marking follows the directive's vocabulary: **required** / **optional**, **secret** /
**non-secret**.
No value here is a secret, and no secret has a default: the library's own `TenancyConfig` reads
`JDLIB_CONTROL_DSN`, `JDLIB_CONTEXT__SIGNING_KEY`, `JDLIB_OIDC__*` and the rest from the
environment, and this module adds only what the *example* needs on top. `config/.env.example`
documents every name with its marking; nothing in the repository carries a value.

Two configuration rules this module keeps, because both are security properties:

* the policy engine's endpoint must be `https://` outside localhost -- the library's `CerbosConfig`
  enforces that, so the example cannot be configured into sending authorization questions in clear;
* a timeout is bounded and positive, so a policy engine that stops answering degrades to a refusal
  rather than hanging a request thread.
"""

from __future__ import annotations

from datetime import timedelta

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from jdlib.security.authz import CerbosConfig


class ExampleSettings(BaseSettings):
    """What the example adds on top of the library's `JDLIB_*` contract."""

    model_config = SettingsConfigDict(
        env_prefix="JDLIB_EXAMPLE_", env_file=None, extra="forbid", frozen=True
    )

    #: required, non-secret -- where the policy engine answers. https, or localhost in development.
    cerbos_endpoint: str = Field(min_length=1)
    #: optional, non-secret -- how long a decision may take before it is treated as degraded.
    cerbos_timeout_seconds: float = Field(default=2.0, gt=0)
    #: optional, non-secret -- the service name spans and logs carry.
    service_name: str = "jdlib-enterprise-example"
    #: optional, non-secret -- an OTLP/HTTP endpoint; empty means "do not trace".
    otel_endpoint: str = ""

    def cerbos_config(self) -> CerbosConfig:
        """The library's Cerbos coordinates, built from the example's values."""
        return CerbosConfig(
            endpoint=self.cerbos_endpoint,
            timeout=timedelta(seconds=self.cerbos_timeout_seconds),
        )
