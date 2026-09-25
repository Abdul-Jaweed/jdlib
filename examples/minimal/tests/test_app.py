"""What the minimal example claims, checked rather than asserted in prose.

The tests here are the example's contract with a reader:

* the **ops routes answer without credentials** -- a liveness probe that needs a token fails during
  an identity-provider outage and gets the process restarted for it;
* the tenant plane is **mounted**, and every route inside it is guarded by the library's own guard
  or is on a public list stated here. The failure this catches is a route added later without a
  ``require(...)``, which is the mistake a copy-paste example teaches;
* the tenant is never a parameter: the route that reports it takes the context and nothing else;
* a request with no credentials is refused in the one canonical envelope shape, and **readiness
  reports the truth** when its database is unreachable rather than answering "ready".
"""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.routing import APIRoute, Mount
from httpx import ASGITransport, AsyncClient

from examples.minimal.app.main import TENANT_PREFIX

#: Routes inside the tenant plane that are public *on purpose*, named so that adding one is a
#: decision rather than an omission. It is empty: nothing under the mount is reachable without a
#: principal and a tenant, and the ops routes live outside it.
PUBLIC_TENANT_ROUTES: set[str] = set()


def _app() -> Any:
    from examples.minimal.app.main import create_app

    return create_app()


def _tenant_app(app: Any) -> Any:
    mount = next(route for route in app.routes if isinstance(route, Mount))
    assert mount.path == TENANT_PREFIX, f"the tenant plane is mounted at {mount.path}"
    return mount.app


async def _get(app: Any, path: str) -> Any:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://example.invalid") as client:
        return await client.get(path)


def test_the_tenant_plane_is_wired_by_the_library_installer(jdlib_environment: None) -> None:
    from jdlib.tenancy.middleware import TenantMiddleware

    tenant_app = _tenant_app(_app())
    assert any(entry.cls is TenantMiddleware for entry in tenant_app.user_middleware)
    assert tenant_app.state.jdlib_container is not None


def test_every_tenant_route_declares_the_permission_it_requires(jdlib_environment: None) -> None:
    """The guard's own declaration is the only thing that distinguishes guarded from unguarded.

    A first version of this test accepted "a dependency from `jdlib.integrations.fastapi`" -- and
    a mutation proved it decoration: deleting the guard from `/me` left the context accessor,
    which lives in the same module, and the test stayed green.
    """
    tenant_app = _tenant_app(_app())
    routes = [route for route in tenant_app.routes if isinstance(route, APIRoute)]
    assert routes, "the tenant plane has no routes at all"
    for route in routes:
        if route.path in PUBLIC_TENANT_ROUTES:
            continue
        declared = [
            permission
            for dependency in route.dependant.dependencies
            if (permission := getattr(dependency.call, "jdlib_permission", None)) is not None
        ]
        assert declared, (
            f"{route.path} carries no require(...) guard: a route added without one is the "
            "mistake this test exists to catch"
        )


def test_the_tenant_route_takes_the_context_and_never_a_parameter(jdlib_environment: None) -> None:
    """A tenant a caller can name is a tenant a caller can choose."""
    tenant_app = _tenant_app(_app())
    route = next(
        route for route in tenant_app.routes if isinstance(route, APIRoute) and route.path == "/me"
    )
    assert route.dependant.path_params == []
    assert route.dependant.query_params == []
    assert route.dependant.body_params == []


async def test_the_ops_routes_answer_without_credentials(jdlib_environment: None) -> None:
    response = await _get(_app(), "/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


async def test_a_request_with_no_credentials_is_refused_in_the_canonical_envelope(
    jdlib_environment: None,
) -> None:
    response = await _get(_app(), f"{TENANT_PREFIX}/me")
    assert response.status_code == 401
    assert set(response.json()) == {"code", "message", "request_id", "correlation_id"}


async def test_readiness_reports_the_truth_when_its_database_is_unreachable(
    jdlib_environment: None,
) -> None:
    """The test environment's database does not exist, so "ready" would be a lie.

    The status and the body both come from the library: the envelope maps an unreachable database
    to `DEPENDENCY_UNAVAILABLE`, so the example carries no readiness-specific error handling.
    """
    response = await _get(_app(), "/readyz")
    assert response.status_code == 503
    body = response.json()
    assert set(body) == {"code", "message", "request_id", "correlation_id"}
    assert body["code"] == "DEPENDENCY_UNAVAILABLE"


def test_the_example_imports_no_driver_and_no_second_envelope() -> None:
    """The example composes the library; it does not reach past it.

    A driver import here would mean the example had opened its own connection, and a hand-written
    error body would mean a second envelope -- the two things the library exists to remove.
    """
    import ast
    import pathlib

    root = pathlib.Path(__file__).resolve().parents[1] / "app"
    forbidden = {"neo4j", "asyncpg", "psycopg", "psycopg2", "redis"}
    for path in root.glob("*.py"):
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert alias.name.split(".")[0] not in forbidden, (path.name, alias.name)
            elif isinstance(node, ast.ImportFrom) and node.module:
                assert node.module.split(".")[0] not in forbidden, (path.name, node.module)
        assert "JSONResponse" not in source, f"{path.name} builds its own response envelope"


def test_the_app_refuses_to_start_without_a_control_dsn(
    jdlib_environment: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No default DSN: a default is a database the operator did not choose.

    The refusal has to be a sentence at startup, not a connection error at the first request.
    """
    from examples.minimal.app.dsn import control_dsn
    from jdlib import TenancyConfig

    monkeypatch.delenv("JDLIB_CONTROL_DSN", raising=False)
    config = TenancyConfig()  # type: ignore[call-arg]  # filled from the environment

    with pytest.raises(RuntimeError, match="JDLIB_CONTROL_DSN is required"):
        control_dsn(config)
