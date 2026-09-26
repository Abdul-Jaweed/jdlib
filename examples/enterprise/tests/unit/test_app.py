"""What this slice claims, checked.

The claims are structural, and each one is a property a later edit can break silently:

* the ops routes answer **without credentials**, and the tenant plane is **mounted** -- so nothing
  under it is reachable without a principal and a tenant;
* every tenant route **declares a permission**; the context accessor is also a dependency from the
  library, so only the guard's own declaration distinguishes a guarded route from an unguarded one;
* an unauthenticated request is answered in the canonical envelope;
* the policy engine's endpoint is **refused** when it is not https (outside localhost) -- the
  library's rule, proven through the example's own settings, because a deployment that can be
  configured to ask its authorization questions in clear is a deployment that will be.
"""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.routing import APIRoute, Mount
from httpx import ASGITransport, AsyncClient

from examples.enterprise.app.main import API_PREFIX

#: Routes inside the tenant plane that are public *on purpose*. It is empty: nothing under the
#: mount is reachable without a principal and a tenant, and the ops routes live outside it.
PUBLIC_TENANT_ROUTES: set[str] = set()


def _app() -> Any:
    from examples.enterprise.app.main import create_app

    return create_app()


def _api_routes(app: Any) -> list[APIRoute]:
    """Every `APIRoute` under this app, however the framework nests it.

    FastAPI keeps the routes an `include_router` call contributed in their own entry rather than
    flattening them into `app.routes`, so a walk that reads only the top level finds **none** of
    the application's routes -- a check that would pass while proving nothing. The nesting is why
    this helper exists; the assertion that there is at least one route is what caught it.
    """
    found: list[APIRoute] = []
    stack = list(app.routes)
    while stack:
        route = stack.pop()
        if isinstance(route, APIRoute):
            found.append(route)
            continue
        stack.extend(getattr(route, "routes", None) or [])
        original = getattr(route, "original_router", None)
        if original is not None:
            stack.extend(getattr(original, "routes", None) or [])
    return found


def _tenant_app(app: Any) -> Any:
    mount = next(route for route in app.routes if isinstance(route, Mount))
    assert mount.path == API_PREFIX, f"the tenant plane is mounted at {mount.path}"
    return mount.app


async def _get(app: Any, path: str) -> Any:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://example.invalid") as client:
        return await client.get(path)


def test_the_tenant_plane_is_wired_by_the_library_installer(enterprise_environment: None) -> None:
    from jdlib.tenancy.middleware import TenantMiddleware

    tenant_app = _tenant_app(_app())
    assert any(entry.cls is TenantMiddleware for entry in tenant_app.user_middleware)
    assert tenant_app.state.jdlib_container is not None


def test_every_tenant_route_declares_the_permission_it_requires(
    enterprise_environment: None,
) -> None:
    routes = _api_routes(_tenant_app(_app()))
    assert routes, "the tenant plane has no routes at all"
    for route in routes:
        if route.path in PUBLIC_TENANT_ROUTES:
            continue
        declared = [
            permission
            for dependency in route.dependant.dependencies
            if (permission := getattr(dependency.call, "jdlib_permission", None)) is not None
        ]
        assert declared, f"{route.path} carries no require(...) guard"


async def test_the_ops_routes_answer_without_credentials(enterprise_environment: None) -> None:
    response = await _get(_app(), "/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


async def test_a_request_with_no_credentials_is_refused_in_the_canonical_envelope(
    enterprise_environment: None,
) -> None:
    response = await _get(_app(), f"{API_PREFIX}/whoami")
    assert response.status_code == 401
    assert set(response.json()) == {"code", "message", "request_id", "correlation_id"}


def test_a_plaintext_policy_endpoint_is_refused(enterprise_environment: None) -> None:
    """The library's rule, proven through the example's own settings.

    `http://` is allowed only for localhost: an authorization question sent in clear is a question
    whose answer anyone on the path can read -- and can answer.
    """
    from examples.enterprise.app.configuration.settings import ExampleSettings
    from jdlib.security.errors import SecurityConfigurationError

    settings = ExampleSettings(cerbos_endpoint="http://cerbos.internal:3592")
    with pytest.raises(SecurityConfigurationError):
        settings.cerbos_config()
