# Examples

Task-oriented recipes. All of them are distilled from the repository `README.md`
and the test suite, so every snippet is code that runs in this repo's CI.

## 1. Define a tenant resource and read it safely

```python
# myapp/models.py
import uuid
from datetime import datetime

from sqlalchemy import ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from jdlib.models.base import (OwnableByOrg, OwnableByTeam, SoftDelete,
                               TenantBase, TenantRouted, Timestamped)


class Invoice(TenantBase, TenantRouted, Timestamped, SoftDelete,
              OwnableByOrg, OwnableByTeam):
    __tablename__ = "invoices"

    number: Mapped[str] = mapped_column(String(40))
    status: Mapped[str] = mapped_column(String(20), default="draft")


class LineItem(TenantBase, TenantRouted, Timestamped):
    __tablename__ = "line_items"

    invoice_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("invoices.id", ondelete="CASCADE"))
    amount_cents: Mapped[int] = mapped_column()
```

```python
# reading: no tenant_id in the query, ever
from jdlib import TenantRepository, UnitOfWork, current_tenant

async def list_drafts() -> list[Invoice]:
    context = current_tenant()
    async with UnitOfWork(session_factory, context, fence=NullWriteFence()) as session:
        repo = TenantRepository(session, Invoice)
        return await repo.list(Invoice.status == "draft", order_by=Invoice.number)
```

## 2. A granted resource (`resource:share`) — grant and read

```python
from jdlib.authz.access import AccessControl

# owner shares one invoice with a teammate
await access.grant_resource(
    tenant_id, resource_type="invoice", resource_id=invoice.id,
    principal_type="user", principal_id=teammate_id, permission="resource:read",
    actor_id=owner_id, actor_principal=owner_principal,
)

# the teammate can now be authorized for exactly that invoice
decision = await authorize("resource:read", ResourceRef("invoice", invoice.id),
                           enforcer=enforcer, session=session)
```

`grant_resource` needs `resource:share` **and** the permission being handed out,
the resource type must be registered, and the resource must exist, belong to the
tenant and not be soft-deleted (otherwise `InvalidReference` /`CrossTenantReferenceError`).

## 3. Register a resource type and a custom permission

```python
from jdlib.authz.permissions import PermissionCatalog
from jdlib.authz.resource_types import ResourceTypeDefinition, ResourceTypeRegistry
from jdlib.control.enums import ScopeType

catalog = PermissionCatalog.with_builtins()
catalog.register(Permission(
    code="invoice:approve",
    namespace="invoice",
    allowed_scopes=frozenset({ScopeType.TENANT, ScopeType.ORG, ScopeType.TEAM}),
    description="Approve an invoice",
))

registry = ResourceTypeRegistry()
registry.register(ResourceTypeDefinition(
    resource_type="invoice", model=Invoice,
    tenant_owned=True, tenant_routed=True, permission_namespace="invoice",
))
```

Now `AccessControl.grant_resource(..., permission="invoice:approve")` works, and a
namespace mismatch raises `InvalidResourcePermission`.

## 4. Provision a tenant (schema-per-tenant) and serve it

```python
from jdlib.control.enums import DeprovisionMode, PlacementStrategy
from jdlib.control.registry import RegistryWriteFence, TenantRegistry
from jdlib.persistence.strategies.schema import SchemaPerTenantStrategy
from jdlib.persistence.strategies.shared import SharedSchemaStrategy

strategies = {
    PlacementStrategy.SHARED: SharedSchemaStrategy(engine, "public", rls=RlsConfig(enabled=True, app_role="app")),
    PlacementStrategy.SCHEMA: SchemaPerTenantStrategy(engine, runner),
}
registry = TenantRegistry(session_factory=control_sessions, strategies=strategies,
                          runner=runner, audit=audit)
fence = RegistryWriteFence(session_factory=control_sessions)

tenant = await registry.create(slug="acme", name="Acme", strategy=PlacementStrategy.SCHEMA,
                               target_handle="t_acme")
tenant = await registry.provision(tenant.id)
record = await registry.assert_servable(tenant.id)     # raise if suspended/relocating
```

## 5. Turn RLS on for a shared placement

```python
from jdlib.persistence.strategies.rls import emit_rls_policies, verify_rls

# in YOUR Alembic migration, after creating the tenant tables:
with engine.begin() as connection:
    connection.execute(sa.text('SET search_path TO "public"'))
    emit_rls_policies(connection, metadata=TenantBase.metadata, app_role="acme_app")

verify_rls(engine, "acme_app", metadata=TenantBase.metadata)
```

The application role must not be superuser nor `BYPASSRLS`, and the shared
strategy must be constructed with `rls=RlsConfig(enabled=True, app_role="acme_app")`
so `app.tenant_id` is set per transaction:

```
SET LOCAL app.tenant_id = '<uuid>'   -- via SELECT set_config('app.tenant_id', $1, true)
```

## 6. A background job that keeps tenant context

```python
from jdlib.context import EnvelopeCodec
from jdlib.tenancy.jobs import ContextPropagator, tenant_job

propagator = ContextPropagator(codec=EnvelopeCodec(config.context.signing_key.get_secret_value()),
                               principals=principals, tenants=tenants,
                               servability=registry, entitlements=entitlements)

token = codec.encode(context)          # producer: HMAC'd tenant + principal + ids + TTL

@tenant_job(propagator)
async def send_digest(envelope: str, user_id: uuid.UUID) -> None:
    context = current_tenant()         # reconstructed, re-validated at execution time
    async with UnitOfWork(session_factory_for(context), context, fence=fence) as session:
        ...
```

## 7. FastAPI: guard a route and read data

```python
@app.get("/invoices", dependencies=[Depends(require("resource:read"))])
async def list_invoices(uow: UnitOfWork = Depends(get_uow)) -> list[dict]:
    async with uow as session:
        invoices = await TenantRepository(session, Invoice).list()
        return [{"number": i.number} for i in invoices]
```

Full wiring (middleware, container, PDP per request) is in
[api/fastapi.md](api/fastapi.md).

## 8. Operator commands

```bash
JDLIB_CONTROL_DSN="postgresql+asyncpg://…" jdlib tenant create \
    --slug acme --name "Acme" --strategy schema --target-handle t_acme
JDLIB_CONTROL_DSN="…" jdlib tenant provision <uuid>
JDLIB_CONTROL_DSN="…" jdlib db upgrade-tenants
JDLIB_CONTROL_DSN="…" jdlib schema lint --rls
JDLIB_CONTROL_DSN="…" jdlib rls install --schema public --app-role acme_app
```

## 9. Test your app against a real database

```python
# conftest.py — extend the shipped fixtures with your models
from jdlib.testing.pytest_plugin import jdlib_test_models

@pytest.fixture()
def jdlib_models() -> tuple[str, ...]:
    return (*jdlib_test_models(), "myapp.models")
```

```python
async def test_isolation(jdlib_session_factory, acme_context, globex_context):
    await assert_tenant_isolated(jdlib_session_factory, acme_context, globex_context,
                                 Invoice, number="INV-1")
    await assert_cross_tenant_write_rejected(jdlib_session_factory, acme_context,
                                            Invoice, number="INV-2")
```

```bash
JDLIB_TEST_DATABASE_URL="postgresql+psycopg://jd:pw@localhost:5432/jdlib_test" \
  pytest -q
```

## 10. Fail loudly instead of leaking: what to expect

```python
await session.execute(sa.text("SELECT * FROM invoices"))       # UnscopedRawSql
await session.execute(sa.update(Invoice).values(status="x"))   # UnscopedBulkOperation
session.add(Invoice(number="X", tenant_id=other_tenant))       # CrossTenantReferenceError (on flush)
await session.raw_sql(sa.text("DELETE FROM invoices WHERE 1=1"))  # UnscopedRawSql
```

Each of these is a designed failure with a message that names the sanctioned
alternative (`raw_sql`, `update_where`, `aliased(Entity)`), and each has a test.
