"""Phase 1 security core: SecurityContext and request/correlation context.

Spec refs: #6 (unified SecurityContext), #34/#79 (request, correlation and
trace propagation), #38/#92 (never collapse identities, never trust ambient
state).
"""

from __future__ import annotations

import asyncio
import contextvars
import uuid
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime

import pytest

from jdlib.context import (
    Principal,
    PrincipalKind,
    TenantContext,
    context_scope,
    current_tenant,
)
from jdlib.control.enums import PlacementStrategy
from jdlib.errors import AuthenticationError, MissingTenantContext
from jdlib.security.context import (
    AuthMethod,
    RequestIds,
    SecurityContext,
    TokenMetadata,
    current_security_context,
    current_security_context_or_none,
    new_request_ids,
    security_context_scope,
)
from jdlib.security.errors import SecurityCode, security_code

TENANT_ID = uuid.UUID("11111111-1111-1111-1111-111111111111")


def _principal(**overrides: object) -> Principal:
    values: dict[str, object] = {"kind": PrincipalKind.USER, "id": uuid.uuid4()}
    values.update(overrides)
    return Principal(**values)  # type: ignore[arg-type]


def _tenant_context(**overrides: object) -> TenantContext:
    values: dict[str, object] = {
        "tenant_id": TENANT_ID,
        "tenant_slug": "acme",
        "strategy": PlacementStrategy.SHARED,
        "principal": _principal(),
        "request_id": "req-1",
        "correlation_id": "corr-1",
        "trace_id": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
    }
    values.update(overrides)
    return TenantContext(**values)  # type: ignore[arg-type]


# --- Request identity -------------------------------------------------------


def test_new_request_ids_generates_correlation_from_request_id() -> None:
    ids = new_request_ids()
    assert ids.request_id
    assert ids.correlation_id == ids.request_id
    assert ids.trace_id is None


def test_request_ids_are_validated() -> None:
    with pytest.raises(ValueError):
        RequestIds(request_id="", correlation_id="c")
    with pytest.raises(ValueError):
        RequestIds(request_id="a" * 129, correlation_id="c")
    with pytest.raises(ValueError):
        RequestIds(request_id="bad\nvalue", correlation_id="c")
    with pytest.raises(ValueError):
        RequestIds(request_id="ok", correlation_id="bad\x00value")


def test_request_ids_default_correlation_to_request_id() -> None:
    ids = RequestIds(request_id="req-9", correlation_id=None)
    assert ids.correlation_id == "req-9"


# --- Construction -----------------------------------------------------------


def test_anonymous_principal_cannot_be_constructed_silently() -> None:
    anonymous = Principal(kind=PrincipalKind.ANONYMOUS, id=uuid.uuid4())
    with pytest.raises(AuthenticationError):
        SecurityContext(
            principal=anonymous,
            request_ids=new_request_ids(),
            auth_method=AuthMethod.JWT,
        )


def test_none_auth_method_cannot_be_constructed_silently() -> None:
    tenant = _tenant_context()
    with pytest.raises(AuthenticationError):
        SecurityContext(
            principal=tenant.principal,
            request_ids=new_request_ids(),
            auth_method=AuthMethod.NONE,
        )


def test_identity_is_required_for_direct_construction() -> None:
    # A context cannot exist without an identity: no silent unauthenticated default.
    with pytest.raises(TypeError):
        SecurityContext(auth_method=AuthMethod.JWT)  # type: ignore[call-arg]


def test_explicit_anonymous_factory_is_available() -> None:
    context = SecurityContext.anonymous()
    assert context.authenticated is False
    assert context.principal.kind is PrincipalKind.ANONYMOUS
    assert context.auth_method is AuthMethod.NONE
    assert context.token_metadata is None
    assert context.request_id == context.correlation_id


def test_anonymous_context_requires_a_tenant_explicitly() -> None:
    context = SecurityContext.anonymous()
    assert context.tenant is None
    assert context.tenant_id is None
    assert context.privilege is None
    with pytest.raises(MissingTenantContext):
        context.require_tenant()


def test_authenticated_context_from_tenant_context_does_not_duplicate_state() -> None:
    tenant = _tenant_context()
    metadata = TokenMetadata(
        issuer="https://id.example.com",
        audience="jdlib-api",
        subject="user-123",
        token_type="Bearer",
        jti="jti-1",
        expires_at=datetime(2030, 1, 1, tzinfo=UTC),
        scopes=frozenset({"documents:read"}),
        client_id="app-1",
    )
    context = SecurityContext.from_tenant_context(
        tenant, auth_method=AuthMethod.JWT, token_metadata=metadata
    )
    assert context.authenticated is True
    assert context.principal is tenant.principal
    assert context.tenant is tenant
    assert context.request_id == tenant.request_id
    assert context.correlation_id == tenant.correlation_id
    assert context.trace_id == tenant.trace_id
    assert context.tenant_id == tenant.tenant_id
    assert context.token_metadata is metadata
    assert context.require_tenant() is tenant


def test_token_metadata_cannot_carry_raw_credentials() -> None:
    with pytest.raises(TypeError):
        TokenMetadata(access_token="eyJhbGciOiJIUzI1NiJ9.secret")  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        TokenMetadata(api_key="jd_live_secret")  # type: ignore[call-arg]


def test_security_context_is_immutable() -> None:
    context = SecurityContext.anonymous()
    with pytest.raises(FrozenInstanceError):
        context.auth_method = AuthMethod.JWT  # type: ignore[misc]


# --- Binding and async isolation -------------------------------------------


def test_current_security_context_fails_closed_when_unset() -> None:
    assert current_security_context_or_none() is None
    with pytest.raises(AuthenticationError) as excinfo:
        current_security_context()
    assert security_code(excinfo.value) is SecurityCode.AUTHENTICATION_REQUIRED


def test_security_context_scope_binds_and_restores() -> None:
    context = SecurityContext.anonymous()
    assert current_security_context_or_none() is None
    with security_context_scope(context):
        assert current_security_context() is context
    assert current_security_context_or_none() is None


def test_security_context_is_task_safe() -> None:
    async def worker(name: str) -> object:
        ids = RequestIds(request_id=f"req-{name}", correlation_id=f"req-{name}")
        context = SecurityContext.anonymous(request_ids=ids)
        with security_context_scope(context):
            await asyncio.sleep(0)
            return current_security_context().request_id

    async def main() -> list[object]:
        return list(await asyncio.gather(worker("a"), worker("b")))

    assert asyncio.run(main()) == ["req-a", "req-b"]


def test_tenant_context_scope_and_security_context_scope_coexist() -> None:
    tenant = _tenant_context()
    security = SecurityContext.from_tenant_context(tenant, auth_method=AuthMethod.API_KEY)
    with context_scope(tenant), security_context_scope(security):
        assert current_tenant() is tenant
        assert current_security_context() is security


def test_contextvar_does_not_leak_between_contexts() -> None:
    var: contextvars.ContextVar[str] = contextvars.ContextVar("probe", default="unset")

    def run() -> str:
        return var.get()

    var.set("outer")
    assert run() == "outer"
