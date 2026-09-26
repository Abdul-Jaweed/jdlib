"""Provisioning: tenants, callers with roles, and keys that are really in the control plane.

The three layers below ask different questions, but they ask them of the same lab, provisioned the
same way the README documents: migrate the control plane, create and provision the tenants, install
the row-level security the operator step installs, then create a caller and hash its key.

A caller here is a **service account with a role and an API key** -- the credential the library's
authenticator verifies, not a token the tests mint in memory and hope the application accepts.
"""

from __future__ import annotations

import asyncio
import secrets
import uuid
from collections.abc import Sequence
from dataclasses import dataclass, field

import sqlalchemy as sa
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from examples.enterprise.app.dataplane import install_tenant_rls, shared_strategy
from examples.enterprise.app.dsn import async_dsn
from examples.enterprise.tests.support.environment import MIGRATION_DSN, RUNTIME_DSN
from jdlib.authn.apikey import hash_api_key_secret
from jdlib.config import TenancyConfig
from jdlib.context import Principal, PrincipalKind, TenantContext
from jdlib.control.audit import DatabaseAuditSink
from jdlib.control.enums import PlacementStrategy
from jdlib.control.models import ApiKey, Role, RoleBinding, RolePermission, ServiceAccount
from jdlib.control.registry import TenantRegistry
from jdlib.migrations.runner import MigrationRunner
from jdlib.tenancy.resolution import RequestInfo

#: What each role *is*, in the control plane's vocabulary. The policy engine is what decides --
#: `CerbosEnforcer` sends the caller's roles and `config/cerbos/policies/` answers -- so these rows
#: are the directory's account of the role, and a fixture that gave a role a permission the policy
#: does not grant would be a fixture that lies about the deployment.
ROLE_PERMISSIONS: dict[str, tuple[str, ...]] = {
    "support": ("tenant:read", "audit:read", "resource:read", "graph:read"),
    "operator": (
        "tenant:read",
        "audit:read",
        "resource:read",
        "graph:read",
        "resource:write",
        "graph:write",
    ),
    "admin": (
        "tenant:read",
        "audit:read",
        "resource:read",
        "graph:read",
        "resource:write",
        "graph:write",
        "tenant:suspend",
        "tenant:archive",
        "data:export",
    ),
}


@dataclass(frozen=True, slots=True)
class Caller:
    """A provisioned caller: which tenant, which principal, which key -- and nothing else.

    `context()` is the tenant context the *application* builds for this caller, and `request()` is
    what a surface begins with: the credential, and no claim the caller could have written itself.
    """

    label: str
    tenant_id: uuid.UUID
    tenant_slug: str
    principal_id: uuid.UUID
    role: str
    token: str

    def context(self) -> TenantContext:
        """The tenant context the application uses for this caller.

        The slug is the one the registry created, not one derived from the id: a harness that
        invented a plausible slug would pass every assertion that compared it with itself, and fail
        the one assertion that compared it with what the application resolved.
        """
        return TenantContext(
            tenant_id=self.tenant_id,
            tenant_slug=self.tenant_slug,
            strategy=PlacementStrategy.SHARED,
            principal=Principal(
                kind=PrincipalKind.SERVICE_ACCOUNT,
                id=self.principal_id,
                tenant_id=self.tenant_id,
            ),
            request_id=f"req-{uuid.uuid4().hex[:8]}",
            correlation_id=f"corr-{uuid.uuid4().hex[:8]}",
        )

    def request(self, path: str = "mcp://tool/resource_get") -> RequestInfo:
        """The request a surface begins with: the bearer key, and no identity claim."""
        return RequestInfo(
            headers={"authorization": f"Bearer {self.token}"},
            query={},
            path=path,
            host="mcp",
        )

    def forged(self, *, token: str | None = None) -> Caller:
        """This caller with a key the control plane has never seen."""
        salt = uuid.uuid4().hex[:8]
        return Caller(
            label=self.label,
            tenant_id=self.tenant_id,
            tenant_slug=self.tenant_slug,
            principal_id=self.principal_id,
            role=self.role,
            token=token or f"jd.{salt}.{secrets.token_urlsafe(32)}",
        )


@dataclass(frozen=True, slots=True)
class Chain:
    """The two-tenant lab the security and end-to-end layers drive.

    Both callers hold the *same* role, deliberately: with the role held constant, a difference in
    what they can reach is a difference the tenant made, which is the question those layers ask.
    """

    alpha: Caller
    beta: Caller
    extras: tuple[Caller, ...] = field(default=())

    def callers(self) -> tuple[Caller, ...]:
        return (self.alpha, self.beta, *self.extras)


async def wait_for_database(url: str, *, attempts: int = 20) -> None:
    """Wait until the database accepts connections, rather than assuming it does.

    A container that has just initialised a volume answers "the database system is not yet accepting
    connections" for a few seconds, and a suite that connects during that window reports ten errors
    that are all the same race -- which reads like a broken example.
    """
    engine = create_async_engine(async_dsn(url), isolation_level="AUTOCOMMIT")
    try:
        for attempt in range(1, attempts + 1):
            try:
                async with engine.connect() as connection:
                    await connection.execute(sa.text("SELECT 1"))
                return
            except (OperationalError, ConnectionError) as error:
                if attempt == attempts:
                    raise
                print(f"waiting for the database ({attempt}/{attempts}): {error!s:.60}")
                await asyncio.sleep(2)
    finally:
        await engine.dispose()


def mint_key(prefix: str) -> tuple[str, str, str]:
    """A key in the format the library parses: `prefix.salt.secret` -> (token, prefix, secret)."""
    salt = uuid.uuid4().hex[:8]
    secret = secrets.token_urlsafe(32)
    return f"{prefix}.{salt}.{secret}", f"{prefix}.{salt}", secret


async def provision_callers(
    specs: Sequence[tuple[str, str]],
) -> tuple[Caller, ...]:
    """Create one tenant per spec -- `(label, role)` -- and a caller holding that role in it.

    The tenants are created and provisioned through the library's own registry, so the tables and
    the tenant's row exist for the same reasons they would in a deployment.
    """
    config = TenancyConfig()  # type: ignore[call-arg]  # env-filled
    await wait_for_database(MIGRATION_DSN)
    MigrationRunner(MIGRATION_DSN).upgrade_control()

    app_role = sa.engine.make_url(RUNTIME_DSN).username
    assert app_role is not None

    engine = create_async_engine(async_dsn(MIGRATION_DSN))
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    callers: list[Caller] = []
    try:
        registry = TenantRegistry(
            session_factory=sessions,
            strategies={PlacementStrategy.SHARED: shared_strategy(engine)},
            runner=MigrationRunner(MIGRATION_DSN),
            audit=DatabaseAuditSink(sessions),
        )
        run = secrets.token_hex(3)
        for label, role in specs:
            slug = f"live-{label}-{run}"
            tenant = await registry.create(
                slug=slug,
                name=f"Live {label}",
                strategy=PlacementStrategy.SHARED,
                target_handle=f"live-{run}",
            )
            await registry.provision(tenant.id)

            account_id = uuid.uuid4()
            role_id = uuid.uuid4()
            token, key_prefix, secret = mint_key(config.api_keys.prefix)
            async with sessions() as session:
                session.add(
                    ServiceAccount(
                        tenant_id=tenant.id,
                        id=account_id,
                        name=f"{label}-{account_id.hex[:6]}",
                        status="active",
                    )
                )
                session.add(Role(tenant_id=tenant.id, id=role_id, name=role))
                # Flushed before the rows that point at them: the composite foreign keys are
                # declared in the schema, not as ORM relationships, so the unit of work has no
                # dependency to sort by and would insert the referrers first.
                await session.flush()
                for permission in ROLE_PERMISSIONS[role]:
                    session.add(
                        RolePermission(
                            tenant_id=tenant.id,
                            role_id=role_id,
                            permission_code=permission,
                        )
                    )
                session.add(
                    RoleBinding(
                        tenant_id=tenant.id,
                        id=uuid.uuid4(),
                        role_id=role_id,
                        principal_type="service_account",
                        principal_id=account_id,
                        scope_type="tenant",
                    )
                )
                session.add(
                    ApiKey(
                        tenant_id=tenant.id,
                        id=uuid.uuid4(),
                        service_account_id=account_id,
                        key_prefix=key_prefix,
                        key_hash=hash_api_key_secret(secret),
                        status="active",
                    )
                )
                await session.commit()
            callers.append(
                Caller(
                    label=label,
                    tenant_id=tenant.id,
                    tenant_slug=slug,
                    principal_id=account_id,
                    role=role,
                    token=token,
                )
            )
    finally:
        await engine.dispose()

    # The operator step the README documents, run the same way: the runtime role needs the policies
    # to exist, and a lab where only the owner has them is a lab whose isolation tests measure
    # nothing.
    await install_tenant_rls(MIGRATION_DSN, "public", app_role=app_role)
    return tuple(callers)


async def add_caller(tenant: Caller, *, role: str, label: str | None = None) -> Caller:
    """A second caller **in an existing tenant**, holding a different role.

    This is the shape a denial test needs: the same tenant, the same data, and a caller whose role
    is weaker -- so what differs between the two callers is the role and nothing else. The account,
    the role, the binding and the key are created the same way `provision_callers` creates them.
    """
    config = TenancyConfig()  # type: ignore[call-arg]  # env-filled
    engine = create_async_engine(async_dsn(MIGRATION_DSN))
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    account_id = uuid.uuid4()
    role_id = uuid.uuid4()
    token, key_prefix, secret = mint_key(config.api_keys.prefix)
    try:
        async with session_factory() as session:
            session.add(
                ServiceAccount(
                    tenant_id=tenant.tenant_id,
                    id=account_id,
                    name=f"{role}-{account_id.hex[:6]}",
                    status="active",
                )
            )
            session.add(Role(tenant_id=tenant.tenant_id, id=role_id, name=role))
            await session.flush()
            for permission in ROLE_PERMISSIONS[role]:
                session.add(
                    RolePermission(
                        tenant_id=tenant.tenant_id,
                        role_id=role_id,
                        permission_code=permission,
                    )
                )
            session.add(
                RoleBinding(
                    tenant_id=tenant.tenant_id,
                    id=uuid.uuid4(),
                    role_id=role_id,
                    principal_type="service_account",
                    principal_id=account_id,
                    scope_type="tenant",
                )
            )
            session.add(
                ApiKey(
                    tenant_id=tenant.tenant_id,
                    id=uuid.uuid4(),
                    service_account_id=account_id,
                    key_prefix=key_prefix,
                    key_hash=hash_api_key_secret(secret),
                    status="active",
                )
            )
            await session.commit()
    finally:
        await engine.dispose()
    return Caller(
        label=label or f"{tenant.label}-{role}",
        tenant_id=tenant.tenant_id,
        tenant_slug=tenant.tenant_slug,
        principal_id=account_id,
        role=role,
        token=token,
    )


def provision_chain() -> Chain:
    """The two-tenant lab: one caller per tenant, both holding `operator`."""
    callers = asyncio.run(provision_callers((("alpha", "operator"), ("beta", "operator"))))
    return Chain(alpha=callers[0], beta=callers[1])


def row_status(resource_id: uuid.UUID) -> str:
    """One row's status, read as the **owner**: a measurement that does not go through the app.

    The application's own reads are tenant-bound and authorized, which is what makes them evidence
    of what a caller can see. This one is evidence of what *is* -- a denied write that the tenant's
    session could not have observed as unchanged is still a write if the row moved, so the two
    measurements are different questions and both are asked.
    """

    async def _body() -> str:
        engine = create_async_engine(async_dsn(MIGRATION_DSN))
        try:
            async with engine.connect() as connection:
                result = await connection.execute(
                    sa.text("SELECT status FROM resources WHERE id = :id"), {"id": resource_id}
                )
                row = result.first()
                return str(row[0]) if row is not None else "absent"
        finally:
            await engine.dispose()

    return asyncio.run(_body())
