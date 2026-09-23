from __future__ import annotations

import uuid
from typing import Annotated

import httpx
import pytest

fastapi = pytest.importorskip("fastapi")

from jdlib.authn.apikey import ApiKeyAuthenticator, hash_api_key_secret  # noqa: E402
from jdlib.authn.wiring import (  # noqa: E402
    EntitlementAdapter,
    PrincipalDirectoryAdapter,
    TenantDirectoryAdapter,
)
from jdlib.authz.reader import ControlAccessReader  # noqa: E402
from jdlib.config import ContextConfig  # noqa: E402
from jdlib.context import ContextFactory, TenantContext  # noqa: E402
from jdlib.control.audit import RecordingPlatformAudit  # noqa: E402
from jdlib.control.models import (  # noqa: E402
    ApiKey,
    ServiceAccount,
    Tenant,
    TenantMigrationState,
    TenantPlacement,
)
from jdlib.control.registry import TenantRegistry  # noqa: E402
from jdlib.errors import PermissionDenied  # noqa: E402
from jdlib.integrations.fastapi import (  # noqa: E402
    JdlibContainer,
    get_context,
    get_uow,
    install,
    require,
)
from jdlib.tenancy.resolution import ApiKeyResolver, HeaderResolver, ResolverChain  # noqa: E402
from tests.support.context_fakes import FrozenClock, RecordingPrivilegeAudit  # noqa: E402


class _Runner:
    def upgrade_tenant(self, schema: str, revision: str = "head") -> None:
        return None

    def tenant_version(self, schema: str) -> str | None:
        return "0001_tenant_baseline"


class _OperatorStub:
    async def authorize(self, principal: object, capability: str) -> bool:
        return False


async def _build_app(control_session_factory, container: JdlibContainer | None = None):
    pinned_tenant = uuid.uuid4()
    other_tenant = uuid.uuid4()
    pinned_slug = f"fapi-{pinned_tenant.hex[:8]}"
    other_slug = f"fapi-{other_tenant.hex[:8]}"
    account_id = uuid.uuid4()
    secret = "s3cret"
    prefix = f"jd.k{uuid.uuid4().hex[:8]}"
    async with control_session_factory() as session:
        for tenant_id, slug in ((pinned_tenant, pinned_slug), (other_tenant, other_slug)):
            session.add(Tenant(id=tenant_id, slug=slug, name=slug, status="active"))
            await session.flush()
            session.add(
                TenantPlacement(tenant_id=tenant_id, strategy="shared", target_handle="default")
            )
            session.add(
                TenantMigrationState(
                    tenant_id=tenant_id,
                    current_version="0001_tenant_baseline",
                    desired_version="0001_tenant_baseline",
                    status="success",
                )
            )
        session.add(
            ServiceAccount(tenant_id=pinned_tenant, id=account_id, name="svc", status="active")
        )
        await session.flush()
        session.add(
            ApiKey(
                tenant_id=pinned_tenant,
                id=uuid.uuid4(),
                service_account_id=account_id,
                key_prefix=prefix,
                key_hash=hash_api_key_secret(secret),
                status="active",
            )
        )
        await session.commit()
    registry = TenantRegistry(
        session_factory=control_session_factory,
        strategies={},
        runner=_Runner(),
        audit=RecordingPlatformAudit(),
        desired_version="0001_tenant_baseline",
    )
    reader = ControlAccessReader(control_session_factory)
    factory = ContextFactory(
        config=ContextConfig(signing_key="k"),
        principals=PrincipalDirectoryAdapter(reader),
        tenants=TenantDirectoryAdapter(registry),
        servability=registry,
        entitlements=EntitlementAdapter(reader),
        operators=_OperatorStub(),
        audit=RecordingPrivilegeAudit(),
        clock=FrozenClock(),
    )
    authenticator = ApiKeyAuthenticator(
        session_factory=control_session_factory,
        audit=RecordingPlatformAudit(),
        clock=FrozenClock(),
    )
    app = fastapi.FastAPI()
    install(
        app,
        factory=factory,
        chain=ResolverChain([HeaderResolver(name="X-Tenant-Slug"), ApiKeyResolver()]),
        principal_provider=authenticator.authenticate,
        container=container,
    )

    @app.get("/")
    async def whoami(
        context: Annotated[TenantContext, fastapi.Depends(get_context)],
    ) -> dict[str, str]:
        return {"tenant": str(context.tenant_id)}

    @app.get("/denied")
    async def denied() -> None:
        raise PermissionDenied("nope")

    return app, pinned_tenant, other_slug, f"Bearer {prefix}.{secret}"


def _client(app) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://jdlib.test"
    )


async def test_request_resolves_api_key_tenant(control_session_factory):
    app, pinned_tenant, _, token = await _build_app(control_session_factory)
    async with _client(app) as client:
        response = await client.get("/", headers={"Authorization": token})
    assert response.status_code == 200
    assert response.json() == {"tenant": str(pinned_tenant)}


async def test_request_without_credentials_returns_401_json(control_session_factory):
    app, _, _, _ = await _build_app(control_session_factory)
    async with _client(app) as client:
        response = await client.get("/")
    assert response.status_code == 401
    assert response.json() == {
        "error": "AuthenticationError",
        "detail": "no credentials presented",
    }


async def test_key_pinned_to_other_tenant_with_header_override_returns_404(
    control_session_factory,
):
    app, _, other_slug, token = await _build_app(control_session_factory)
    async with _client(app) as client:
        response = await client.get(
            "/", headers={"Authorization": token, "X-Tenant-Slug": other_slug}
        )
    assert response.status_code == 404
    assert response.json()["error"] == "TenantAccessDenied"


async def test_route_jdlib_error_maps_to_json_via_handler(control_session_factory):
    app, _, _, token = await _build_app(control_session_factory)
    async with _client(app) as client:
        response = await client.get("/denied", headers={"Authorization": token})
    assert response.status_code == 403
    assert response.json() == {"error": "PermissionDenied", "detail": "nope"}


class _FakeEnforcer:
    def __init__(self) -> None:
        self.calls: list[tuple[str, object]] = []

    async def require(self, permission: str, target: object, *, session: object) -> None:
        self.calls.append((permission, session))


class _DenyingEnforcer:
    async def require(self, permission: str, target: object, *, session: object) -> None:
        raise PermissionDenied(f"{permission}: denied by policy")


class _FakeUow:
    async def __aenter__(self) -> str:
        return "tenant-session"

    async def __aexit__(self, *exc: object) -> None:
        return None


async def test_container_dependencies_enforce_and_yield_uow(control_session_factory):
    enforcer = _FakeEnforcer()
    container = JdlibContainer(
        session_factory=control_session_factory,
        uow_factory=_FakeUow,
        enforcer=enforcer,  # type: ignore[arg-type]
    )
    app, _, _, token = await _build_app(control_session_factory, container=container)

    @app.get("/guarded", dependencies=[fastapi.Depends(require("invoice.read"))])
    async def guarded() -> dict[str, str]:
        return {"guarded": "yes"}

    @app.get("/uow")
    async def uow_route(uow: Annotated[object, fastapi.Depends(get_uow)]) -> dict[str, str]:
        async with uow as session:
            return {"session": str(session)}

    async with _client(app) as client:
        guarded_response = await client.get("/guarded", headers={"Authorization": token})
        uow_response = await client.get("/uow", headers={"Authorization": token})

    assert guarded_response.status_code == 200
    assert guarded_response.json() == {"guarded": "yes"}
    assert enforcer.calls == [("invoice.read", "tenant-session")]
    assert uow_response.json() == {"session": "tenant-session"}


async def test_denied_require_returns_403_json(control_session_factory):
    container = JdlibContainer(
        session_factory=control_session_factory,
        uow_factory=_FakeUow,
        enforcer=_DenyingEnforcer(),  # type: ignore[arg-type]
    )
    app, _, _, token = await _build_app(control_session_factory, container=container)

    @app.get("/guarded-denied", dependencies=[fastapi.Depends(require("invoice.read"))])
    async def guarded_denied() -> dict[str, str]:
        return {"guarded": "no"}

    async with _client(app) as client:
        response = await client.get("/guarded-denied", headers={"Authorization": token})

    assert response.status_code == 403
    assert response.json() == {
        "error": "PermissionDenied",
        "detail": "invoice.read: denied by policy",
    }
