from __future__ import annotations

import uuid
from datetime import datetime

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import ARRAY, CITEXT, INET, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from jdlib._uuid import uuid7
from jdlib.control.base import ControlBase
from jdlib.control.enums import (
    ActorType,
    ApiKeyStatus,
    AuditSeverity,
    InvitationStatus,
    MembershipStatus,
    MigrationStatus,
    OperatorLevel,
    PlacementStrategy,
    PrincipalType,
    RelocationPhase,
    ScopeType,
    TenantStatus,
    sql_in,
)


class Tenant(ControlBase):
    __tablename__ = "tenants"

    id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, primary_key=True, default=uuid7)
    slug: Mapped[str] = mapped_column(sa.Text, nullable=False, unique=True)
    name: Mapped[str] = mapped_column(sa.Text, nullable=False)
    status: Mapped[str] = mapped_column(
        sa.Text, nullable=False, default=TenantStatus.PROVISIONING.value
    )
    suspended_reason: Mapped[str | None] = mapped_column(sa.Text)
    parent_tenant_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.Uuid, sa.ForeignKey("tenants.id", ondelete="RESTRICT")
    )
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=False,
        server_default=sa.func.now(),
        onupdate=sa.func.now(),
    )
    suspended_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    archived_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))

    __table_args__ = (
        sa.CheckConstraint(sql_in("status", TenantStatus), name="status"),
        sa.CheckConstraint("slug ~ '^[a-z0-9][a-z0-9-]{1,62}$'", name="slug_format"),
        sa.Index("ix_tenants_status", "status"),
        sa.Index("ix_tenants_parent_tenant_id", "parent_tenant_id"),
    )


class TenantPlacement(ControlBase):
    __tablename__ = "tenant_placements"

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid, sa.ForeignKey("tenants.id", ondelete="RESTRICT"), primary_key=True
    )
    strategy: Mapped[str] = mapped_column(sa.Text, nullable=False)
    target_handle: Mapped[str] = mapped_column(sa.Text, nullable=False)
    region: Mapped[str | None] = mapped_column(sa.Text)
    updated_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=False,
        server_default=sa.func.now(),
        onupdate=sa.func.now(),
    )

    __table_args__ = (
        sa.CheckConstraint(sql_in("strategy", PlacementStrategy), name="strategy"),
    )


class TenantMigrationState(ControlBase):
    __tablename__ = "tenant_migration_states"

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid, sa.ForeignKey("tenants.id", ondelete="RESTRICT"), primary_key=True
    )
    current_version: Mapped[str | None] = mapped_column(sa.Text)
    desired_version: Mapped[str] = mapped_column(sa.Text, nullable=False)
    status: Mapped[str] = mapped_column(
        sa.Text, nullable=False, default=MigrationStatus.PENDING.value
    )
    last_error: Mapped[str | None] = mapped_column(sa.Text)
    updated_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=False,
        server_default=sa.func.now(),
        onupdate=sa.func.now(),
    )

    __table_args__ = (
        sa.CheckConstraint(sql_in("status", MigrationStatus), name="status"),
    )


class TenantRelocation(ControlBase):
    __tablename__ = "tenant_relocations"

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid, sa.ForeignKey("tenants.id", ondelete="RESTRICT"), primary_key=True
    )
    id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, primary_key=True, default=uuid7)
    from_strategy: Mapped[str] = mapped_column(sa.Text, nullable=False)
    from_target_handle: Mapped[str] = mapped_column(sa.Text, nullable=False)
    from_region: Mapped[str | None] = mapped_column(sa.Text)
    to_strategy: Mapped[str] = mapped_column(sa.Text, nullable=False)
    to_target_handle: Mapped[str] = mapped_column(sa.Text, nullable=False)
    to_region: Mapped[str | None] = mapped_column(sa.Text)
    status: Mapped[str] = mapped_column(
        sa.Text, nullable=False, default=RelocationPhase.PENDING.value
    )
    started_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )
    verified_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    flipped_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    error: Mapped[str | None] = mapped_column(sa.Text)
    created_by: Mapped[uuid.UUID | None] = mapped_column(sa.Uuid)

    __table_args__ = (
        sa.CheckConstraint(sql_in("from_strategy", PlacementStrategy), name="from_strategy"),
        sa.CheckConstraint(sql_in("to_strategy", PlacementStrategy), name="to_strategy"),
        sa.CheckConstraint(sql_in("status", RelocationPhase), name="status"),
        sa.Index("ix_tenant_relocations_tenant_id_status", "tenant_id", "status"),
        sa.Index(
            "uq_tenant_relocations_active",
            "tenant_id",
            unique=True,
            postgresql_where=sa.text(
                "status NOT IN ('completed', 'failed', 'rolled_back')"
            ),
        ),
    )


class User(ControlBase):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, primary_key=True, default=uuid7)
    email: Mapped[str | None] = mapped_column(CITEXT)
    display_name: Mapped[str | None] = mapped_column(sa.Text)
    locale: Mapped[str | None] = mapped_column(sa.Text)
    status: Mapped[str] = mapped_column(sa.Text, nullable=False, default="active")
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=False,
        server_default=sa.func.now(),
        onupdate=sa.func.now(),
    )

    __table_args__ = (
        sa.CheckConstraint("status IN ('active','suspended','deleted')", name="status"),
        sa.Index(
            "uq_users_email",
            "email",
            unique=True,
            postgresql_where=sa.text("email IS NOT NULL"),
        ),
    )


class IdentityLink(ControlBase):
    __tablename__ = "identity_links"

    id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, primary_key=True, default=uuid7)
    user_id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid, sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    issuer: Mapped[str] = mapped_column(sa.Text, nullable=False)
    subject: Mapped[str] = mapped_column(sa.Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )
    last_login_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))

    __table_args__ = (sa.UniqueConstraint("issuer", "subject"),)


class PlatformOperator(ControlBase):
    __tablename__ = "platform_operators"

    user_id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid, sa.ForeignKey("users.id", ondelete="RESTRICT"), primary_key=True
    )
    level: Mapped[str] = mapped_column(sa.Text, nullable=False)
    granted_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )
    granted_by_user_id: Mapped[uuid.UUID | None] = mapped_column(sa.Uuid)

    __table_args__ = (sa.CheckConstraint(sql_in("level", OperatorLevel), name="level"),)


class ServiceAccount(ControlBase):
    __tablename__ = "service_accounts"

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid, sa.ForeignKey("tenants.id", ondelete="RESTRICT"), primary_key=True
    )
    id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, primary_key=True, default=uuid7)
    name: Mapped[str] = mapped_column(sa.Text, nullable=False)
    status: Mapped[str] = mapped_column(sa.Text, nullable=False, default="active")
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=False,
        server_default=sa.func.now(),
        onupdate=sa.func.now(),
    )

    __table_args__ = (
        sa.UniqueConstraint("tenant_id", "name"),
        sa.CheckConstraint("status IN ('active','suspended','deleted')", name="status"),
    )


class ApiKey(ControlBase):
    __tablename__ = "api_keys"

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid, sa.ForeignKey("tenants.id", ondelete="RESTRICT"), primary_key=True
    )
    id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, primary_key=True, default=uuid7)
    service_account_id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, nullable=False)
    key_prefix: Mapped[str] = mapped_column(sa.Text, nullable=False)
    key_hash: Mapped[str] = mapped_column(sa.Text, nullable=False)
    scopes: Mapped[list[str] | None] = mapped_column(ARRAY(sa.Text))
    status: Mapped[str] = mapped_column(sa.Text, nullable=False, default="active")
    expires_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    last_used_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )
    revoked_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))

    __table_args__ = (
        sa.ForeignKeyConstraint(
            ["tenant_id", "service_account_id"],
            ["service_accounts.tenant_id", "service_accounts.id"],
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint("key_prefix"),
        sa.CheckConstraint(sql_in("status", ApiKeyStatus), name="status"),
        sa.Index("ix_api_keys_tenant_id_service_account_id", "tenant_id", "service_account_id"),
    )


class Membership(ControlBase):
    __tablename__ = "memberships"

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid, sa.ForeignKey("tenants.id", ondelete="RESTRICT"), primary_key=True
    )
    id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, primary_key=True, default=uuid7)
    user_id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid, sa.ForeignKey("users.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    status: Mapped[str] = mapped_column(sa.Text, nullable=False, default="active")
    joined_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )
    suspended_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))

    __table_args__ = (
        sa.UniqueConstraint("tenant_id", "user_id"),
        sa.CheckConstraint(sql_in("status", MembershipStatus), name="status"),
    )


class Role(ControlBase):
    __tablename__ = "roles"

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid, sa.ForeignKey("tenants.id", ondelete="RESTRICT"), primary_key=True
    )
    id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, primary_key=True, default=uuid7)
    name: Mapped[str] = mapped_column(sa.Text, nullable=False)
    description: Mapped[str | None] = mapped_column(sa.Text)
    is_system: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=False,
        server_default=sa.func.now(),
        onupdate=sa.func.now(),
    )

    __table_args__ = (sa.UniqueConstraint("tenant_id", "name"),)


class RolePermission(ControlBase):
    __tablename__ = "role_permissions"

    tenant_id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, primary_key=True)
    role_id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, primary_key=True)
    permission_code: Mapped[str] = mapped_column(sa.Text, primary_key=True)

    __table_args__ = (
        sa.ForeignKeyConstraint(
            ["tenant_id", "role_id"],
            ["roles.tenant_id", "roles.id"],
            ondelete="CASCADE",
        ),
        sa.Index("ix_role_permissions_tenant_id_permission_code", "tenant_id", "permission_code"),
    )


class RoleBinding(ControlBase):
    __tablename__ = "role_bindings"

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid, sa.ForeignKey("tenants.id", ondelete="RESTRICT"), primary_key=True
    )
    id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, primary_key=True, default=uuid7)
    role_id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, nullable=False)
    principal_type: Mapped[str] = mapped_column(sa.Text, nullable=False)
    principal_id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, nullable=False)
    scope_type: Mapped[str] = mapped_column(sa.Text, nullable=False)
    scope_id: Mapped[uuid.UUID | None] = mapped_column(sa.Uuid)
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )
    created_by: Mapped[uuid.UUID | None] = mapped_column(sa.Uuid)

    __table_args__ = (
        sa.ForeignKeyConstraint(
            ["tenant_id", "role_id"],
            ["roles.tenant_id", "roles.id"],
            ondelete="RESTRICT",
        ),
        sa.UniqueConstraint(
            "tenant_id",
            "role_id",
            "principal_type",
            "principal_id",
            "scope_type",
            "scope_id",
            postgresql_nulls_not_distinct=True,
        ),
        sa.CheckConstraint(sql_in("principal_type", PrincipalType), name="principal_type"),
        sa.CheckConstraint(
            "scope_type = 'tenant' AND scope_id IS NULL"
            " OR scope_type IN ('org','team') AND scope_id IS NOT NULL",
            name="scope",
        ),
        sa.Index("ix_role_bindings_tenant_id_principal_type_principal_id",
                 "tenant_id", "principal_type", "principal_id"),
        sa.Index("ix_role_bindings_tenant_id_scope_type_scope_id",
                 "tenant_id", "scope_type", "scope_id"),
    )


class ResourceGrant(ControlBase):
    __tablename__ = "resource_grants"

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid, sa.ForeignKey("tenants.id", ondelete="RESTRICT"), primary_key=True
    )
    id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, primary_key=True, default=uuid7)
    resource_type: Mapped[str] = mapped_column(sa.Text, nullable=False)
    resource_id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, nullable=False)
    principal_type: Mapped[str] = mapped_column(sa.Text, nullable=False)
    principal_id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, nullable=False)
    permission_code: Mapped[str] = mapped_column(sa.Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )
    created_by: Mapped[uuid.UUID | None] = mapped_column(sa.Uuid)

    __table_args__ = (
        sa.UniqueConstraint(
            "tenant_id",
            "resource_type",
            "resource_id",
            "principal_type",
            "principal_id",
            "permission_code",
        ),
        sa.CheckConstraint(sql_in("principal_type", PrincipalType), name="principal_type"),
        sa.Index("ix_resource_grants_tenant_id_resource_type_resource_id",
                 "tenant_id", "resource_type", "resource_id"),
        sa.Index("ix_resource_grants_tenant_id_principal_type_principal_id",
                 "tenant_id", "principal_type", "principal_id"),
    )


class Invitation(ControlBase):
    __tablename__ = "invitations"

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid, sa.ForeignKey("tenants.id", ondelete="RESTRICT"), primary_key=True
    )
    id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, primary_key=True, default=uuid7)
    email: Mapped[str] = mapped_column(CITEXT, nullable=False)
    scope_type: Mapped[str] = mapped_column(sa.Text, nullable=False)
    scope_id: Mapped[uuid.UUID | None] = mapped_column(sa.Uuid)
    role_id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, nullable=False)
    token_id: Mapped[str] = mapped_column(sa.Text, nullable=False, unique=True)
    token_hash: Mapped[str] = mapped_column(sa.Text, nullable=False)
    status: Mapped[str] = mapped_column(sa.Text, nullable=False, default="pending")
    expires_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    accepted_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    invited_by: Mapped[uuid.UUID | None] = mapped_column(sa.Uuid)
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )

    __table_args__ = (
        sa.ForeignKeyConstraint(
            ["tenant_id", "role_id"],
            ["roles.tenant_id", "roles.id"],
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(sql_in("scope_type", ScopeType), name="scope_type"),
        sa.CheckConstraint(
            "scope_type = 'tenant' AND scope_id IS NULL"
            " OR scope_type IN ('org','team') AND scope_id IS NOT NULL",
            name="scope",
        ),
        sa.CheckConstraint(sql_in("status", InvitationStatus), name="status"),
        sa.Index(
            "uq_invitations_pending",
            "tenant_id",
            "email",
            "scope_type",
            sa.text("COALESCE(scope_id, '00000000-0000-0000-0000-000000000000'::uuid)"),
            unique=True,
            postgresql_where=sa.text("status = 'pending'"),
        ),
    )


class PlatformAuditEvent(ControlBase):
    __tablename__ = "platform_audit_events"

    id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, primary_key=True, default=uuid7)
    tenant_id: Mapped[uuid.UUID | None] = mapped_column(sa.Uuid)
    actor_type: Mapped[str] = mapped_column(sa.Text, nullable=False)
    actor_id: Mapped[uuid.UUID | None] = mapped_column(sa.Uuid)
    action: Mapped[str] = mapped_column(sa.Text, nullable=False)
    target_type: Mapped[str | None] = mapped_column(sa.Text)
    target_id: Mapped[uuid.UUID | None] = mapped_column(sa.Uuid)
    metadata_json: Mapped[dict[str, object]] = mapped_column(
        "metadata", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")
    )
    ip: Mapped[str | None] = mapped_column(INET)
    request_id: Mapped[str | None] = mapped_column(sa.Text)
    correlation_id: Mapped[str | None] = mapped_column(sa.Text)
    trace_id: Mapped[str | None] = mapped_column(sa.Text)
    severity: Mapped[str] = mapped_column(sa.Text, nullable=False, default="info")
    occurred_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )

    __table_args__ = (
        sa.CheckConstraint(sql_in("actor_type", ActorType), name="actor_type"),
        sa.CheckConstraint(sql_in("severity", AuditSeverity), name="severity"),
        sa.Index("ix_platform_audit_events_occurred_at", "occurred_at"),
        sa.Index("ix_platform_audit_events_tenant_id_occurred_at", "tenant_id", "occurred_at"),
        sa.Index(
            "ix_platform_audit_events_actor_type_actor_id_occurred_at",
            "actor_type",
            "actor_id",
            "occurred_at",
        ),
        sa.Index("ix_platform_audit_events_action_occurred_at", "action", "occurred_at"),
    )
