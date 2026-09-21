import json
import uuid

import pytest

from jdlib.config import ContextConfig
from jdlib.context import ContextFactory, Principal, PrincipalKind, TenantRecord
from jdlib.control.enums import PlacementStrategy, TenantStatus
from jdlib.errors import (
    AuthenticationError,
    AuthorizationError,
    CrossTenantReferenceError,
    JdlibError,
    TenantAccessDenied,
    TenantNotFound,
    TenantSuspended,
)
from jdlib.tenancy.middleware import PrincipalProvider, TenantMiddleware, http_status_for
from jdlib.tenancy.resolution import HeaderResolver, ResolverChain
from tests.support.context_fakes import (
    DictTenants,
    EntitlementsStub,
    FrozenClock,
    OperatorsStub,
    RecordingPrivilegeAudit,
    ServabilityStub,
    StaticPrincipals,
)

TENANT_ID = uuid.UUID("00000000-0000-0000-0000-0000000000aa")
USER_ID = uuid.uuid4()


def test_http_status_mapping_is_frozen():
    assert http_status_for(AuthenticationError()) == 401
    assert http_status_for(AuthorizationError()) == 403
    assert http_status_for(TenantNotFound("x")) == 404
    assert http_status_for(TenantAccessDenied("x")) == 404
    assert http_status_for(TenantSuspended("x")) == 423
    assert http_status_for(CrossTenantReferenceError("r", "a", "b")) == 409
    assert http_status_for(JdlibError("other")) == 500


class _Provider:
    def __init__(self, principal: Principal | None) -> None:
        self._principal = principal

    async def __call__(self, request: object) -> Principal | None:
        return self._principal


def _middleware(
    provider: PrincipalProvider, inner, *, active: set[uuid.UUID] | None = None
) -> TenantMiddleware:
    factory = ContextFactory(
        config=ContextConfig(signing_key="k"),
        principals=StaticPrincipals(active if active is not None else {USER_ID}),
        tenants=DictTenants(
            [
                TenantRecord(
                    id=TENANT_ID,
                    slug="acme",
                    status=TenantStatus.ACTIVE,
                    strategy=PlacementStrategy.SHARED,
                )
            ]
        ),
        servability=ServabilityStub(),
        entitlements=EntitlementsStub({(USER_ID, TENANT_ID)}),
        operators=OperatorsStub(),
        audit=RecordingPrivilegeAudit(),
        clock=FrozenClock(),
    )
    return TenantMiddleware(
        inner,
        factory=factory,
        chain=ResolverChain([HeaderResolver(name="X-Tenant-Slug")]),
        principal_provider=provider,
    )


async def _run(
    middleware: TenantMiddleware, headers: list[tuple[bytes, bytes]]
) -> dict[str, object]:
    sent: list[dict[str, object]] = []

    async def receive() -> dict[str, object]:
        return {"type": "http.request"}

    async def send(message: dict[str, object]) -> None:
        sent.append(message)

    scope = {
        "type": "http",
        "method": "GET",
        "path": "/invoices",
        "headers": headers,
        "query_string": b"",
    }
    await middleware(scope, receive, send)
    status = next(m["status"] for m in sent if m["type"] == "http.response.start")
    body = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    return {"status": status, "body": body, "sent": sent}


async def test_happy_path_installs_context_for_inner_app():
    seen: list[str] = []

    async def inner(scope, receive, send):
        from jdlib.context import current_tenant

        seen.append(current_tenant().tenant_slug)
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    middleware = _middleware(_Provider(Principal(kind=PrincipalKind.USER, id=USER_ID)), inner)
    result = await _run(middleware, [(b"x-tenant-slug", b"acme")])
    assert result["status"] == 200
    assert seen == ["acme"]


async def test_missing_principal_is_401():
    async def inner(scope, receive, send):
        raise AssertionError("must not run")

    middleware = _middleware(_Provider(None), inner)
    result = await _run(middleware, [(b"x-tenant-slug", b"acme")])
    assert result["status"] == 401
    assert json.loads(result["body"])["error"] == "AuthenticationError"


async def test_unresolved_tenant_is_404():
    async def inner(scope, receive, send):
        raise AssertionError("must not run")

    middleware = _middleware(_Provider(Principal(kind=PrincipalKind.USER, id=USER_ID)), inner)
    result = await _run(middleware, [])
    assert result["status"] == 404


async def test_denied_principal_is_404():
    async def inner(scope, receive, send):
        raise AssertionError("must not run")

    other_user = uuid.uuid4()
    middleware = _middleware(
        _Provider(Principal(kind=PrincipalKind.USER, id=other_user)), inner, active={other_user}
    )
    result = await _run(middleware, [(b"x-tenant-slug", b"acme")])
    assert result["status"] == 404


async def test_context_is_cleared_after_request():
    async def inner(scope, receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    middleware = _middleware(_Provider(Principal(kind=PrincipalKind.USER, id=USER_ID)), inner)
    await _run(middleware, [(b"x-tenant-slug", b"acme")])
    from jdlib.context import current_tenant
    from jdlib.errors import MissingTenantContext

    with pytest.raises(MissingTenantContext):
        current_tenant()


async def test_non_http_scope_passes_through():
    calls: list[str] = []

    async def inner(scope, receive, send):
        calls.append(scope["type"])

    middleware = _middleware(_Provider(None), inner)
    await middleware({"type": "lifespan"}, None, None)  # type: ignore[arg-type]
    assert calls == ["lifespan"]
