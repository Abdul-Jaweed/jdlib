"""A guard declares the permission it enforces, so a surface can be audited by walking it.

The FastAPI integration exposes two things an application attaches to a route: `get_context` (the
accessor) and `require(...)` (the guard). They live in the same module, so "this dependency came
from jdlib" cannot distinguish a guarded route from an unguarded one -- and that check is exactly
what an application wants to run over its own surface once routes stop fitting in one file.

The marker is an attribute on the returned callable rather than a wrapper object, because FastAPI
holds the callable itself: a wrapper would change what the framework receives.
"""

from __future__ import annotations

import pytest

fastapi = pytest.importorskip("fastapi")

from jdlib.integrations.fastapi import require  # noqa: E402


def test_a_guard_declares_the_permission_it_enforces() -> None:
    assert require("tenant:read").jdlib_permission == "tenant:read"


def test_two_guards_do_not_share_one_declaration() -> None:
    """The marker belongs to the guard, not to the module that built it."""
    assert require("tenant:read").jdlib_permission == "tenant:read"
    assert require("audit:read").jdlib_permission == "audit:read"
