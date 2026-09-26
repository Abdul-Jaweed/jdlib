"""The operator step, without a database: what it refuses and what it must not need.

The bootstrap is where the two roles meet -- the owner's DSN does the work, the runtime DSN names
the role the policies are installed for -- so the interesting cases are the ones where the
environment is incomplete. They are unit tests: `_migration_dsn` decides before anything connects,
so no lab is needed to prove the refusal, and the connection errors a missing lab would raise would
hide it.
"""

from __future__ import annotations

import asyncio

import pytest

from examples.enterprise.app.bootstrap import _migration_dsn, _role_of, bootstrap
from examples.enterprise.app.configuration.settings import ExampleSettings
from jdlib.errors import ProvisioningError


def test_the_serving_settings_do_not_require_the_owners_dsn(
    enterprise_environment: None,
) -> None:
    """The request path constructs its settings with no owner DSN anywhere in the environment.

    This is a design decision, not an accident: a process that serves requests holds the runtime
    role's credentials only. If this ever starts failing, the example has quietly made the owner's
    DSN a requirement for serving.
    """
    settings = ExampleSettings()  # type: ignore[call-arg]  # env-filled
    assert settings.migration_dsn == ""


def test_the_operator_step_refuses_without_the_owners_dsn(enterprise_environment: None) -> None:
    """A refusal that names the variable, before any connection is attempted."""
    with pytest.raises(ProvisioningError) as refusal:
        _migration_dsn()
    assert "JDLIB_EXAMPLE_MIGRATION_DSN" in str(refusal.value)


def test_the_bootstrap_refuses_before_it_connects(enterprise_environment: None) -> None:
    """The whole entry point, which also exercises the module's imports.

    That is how two missing ones were found -- the settings class and the RLS installer, both
    referenced but never imported -- because nothing else in the suite called this function, so the
    `NameError` would have surfaced only in an operator's hands.
    """
    with pytest.raises(ProvisioningError):
        asyncio.run(bootstrap(slug="refused", name="Refused"))


def test_a_dsn_with_no_role_is_refused_by_name() -> None:
    with pytest.raises(ProvisioningError) as refusal:
        _role_of("postgresql://127.0.0.1:5432/db")
    assert "names no role" in str(refusal.value)


def test_the_role_of_a_dsn_is_the_role_the_policies_are_installed_for() -> None:
    assert _role_of("postgresql://jdlib_app:pw@127.0.0.1:45432/jdlib_enterprise") == "jdlib_app"
