from __future__ import annotations

from dataclasses import dataclass

import sqlalchemy as sa
from sqlalchemy import MetaData

from jdlib.control.base import ControlBase
from jdlib.errors import SchemaLintError
from jdlib.models.base import TenantBase, TenantOwned, TenantRouted

GLOBAL_UNIQUE_WHITELIST = {
    ("api_keys", "uq_api_keys_key_prefix"),
    ("invitations", "uq_invitations_token_id"),
    ("tenants", "uq_tenants_slug"),
}

TENANT_ID_REFERENCE_ONLY = {"platform_audit_events"}


@dataclass(frozen=True)
class LintIssue:
    rule: str
    table: str
    message: str


def _tenant_scoped(table: sa.Table) -> bool:
    return "tenant_id" in table.columns and table.name not in TENANT_ID_REFERENCE_ONLY


def _model_tables() -> dict[int, type]:
    found: dict[int, type] = {}

    def walk(cls: type) -> None:
        for subclass in cls.__subclasses__():
            table = getattr(subclass, "__table__", None)
            if table is not None:
                found[id(table)] = subclass
            walk(subclass)

    for root in (ControlBase, TenantBase, TenantOwned):
        walk(root)
    return found


def _model_for(table: sa.Table, known: dict[int, type]) -> type | None:
    registered: type | None = table.info.get("jdlib_model")
    if registered is not None:
        return registered
    return known.get(id(table))


def _cascade_reachable(metadata: MetaData) -> set[str]:
    children: dict[str, set[str]] = {}
    for table in metadata.tables.values():
        for constraint in table.constraints:
            if isinstance(constraint, sa.ForeignKeyConstraint) and constraint.ondelete == "CASCADE":
                children.setdefault(constraint.referred_table.name, set()).add(table.name)
    reached: set[str] = set()
    frontier = list(children.get("tenants", set()))
    while frontier:
        name = frontier.pop()
        if name in reached or name == "tenants":
            continue
        reached.add(name)
        frontier.extend(children.get(name, set()))
    return reached


def lint_metadata(controls: list[MetaData], rls_enabled: bool = False) -> list[LintIssue]:
    issues: list[LintIssue] = []
    known_models = _model_tables()

    for metadata in controls:
        for table in metadata.tables.values():
            if table.name.startswith("alembic_version"):
                continue
            tenant_scoped = _tenant_scoped(table)
            model = _model_for(table, known_models)

            if tenant_scoped:
                pk_names = [column.name for column in table.primary_key.columns]
                if "tenant_id" not in pk_names:
                    issues.append(
                        LintIssue("L1", table.name, "primary key does not include tenant_id")
                    )
                elif pk_names[0] != "tenant_id":
                    issues.append(
                        LintIssue("L4", table.name, "primary key does not lead with tenant_id")
                    )
                if table.columns["tenant_id"].nullable:
                    issues.append(LintIssue("L9", table.name, "tenant_id is nullable"))
                if (
                    model is not None
                    and table.schema is None
                    and not issubclass(model, TenantOwned)
                ):
                    issues.append(
                        LintIssue("L11", table.name, "tenant-scoped model is not TenantOwned")
                    )

            if model is not None:
                if table.schema == "jd_control" and issubclass(model, TenantRouted):
                    issues.append(
                        LintIssue("L19", table.name, "control-plane model must not be TenantRouted")
                    )
                if table.schema is None and not issubclass(model, TenantRouted):
                    issues.append(
                        LintIssue("L17", table.name, "tenant-plane model must be TenantRouted")
                    )

            for constraint in table.constraints:
                if not isinstance(constraint, sa.ForeignKeyConstraint):
                    continue
                target = constraint.referred_table
                if (
                    _tenant_scoped(table)
                    and _tenant_scoped(target)
                    and "tenant_id" not in set(constraint.column_keys)
                ):
                    issues.append(
                        LintIssue("L2", table.name, f"FK {constraint.name} omits tenant_id")
                    )
                if table.schema != target.schema:
                    issues.append(
                        LintIssue("L3", table.name, f"FK {constraint.name} crosses planes")
                    )

            if tenant_scoped:
                for constraint in table.constraints:
                    if isinstance(constraint, sa.UniqueConstraint):
                        columns = {column.name for column in constraint.columns}
                        key = (table.name, constraint.name or "")
                        if "tenant_id" not in columns and key not in GLOBAL_UNIQUE_WHITELIST:
                            issues.append(
                                LintIssue(
                                    "L12",
                                    table.name,
                                    f"unique {constraint.name} is not tenant-scoped",
                                )
                            )
                for index in table.indexes:
                    if not index.unique:
                        continue
                    columns = {column.name for column in index.columns}
                    key = (table.name, index.name or "")
                    if "tenant_id" not in columns and key not in GLOBAL_UNIQUE_WHITELIST:
                        issues.append(
                            LintIssue(
                                "L12",
                                table.name,
                                f"unique index {index.name} is not tenant-scoped",
                            )
                        )

            if (
                rls_enabled
                and table.schema is None
                and (model is None or not issubclass(model, TenantRouted) or not tenant_scoped)
            ):
                issues.append(
                    LintIssue("L13", table.name, "tenant-plane table is not RLS-eligible")
                )

            if "team_id" in table.columns:
                has_check = any(
                    isinstance(constraint, sa.CheckConstraint)
                    and "team_id" in str(constraint.sqltext)
                    and "organization_id" in str(constraint.sqltext)
                    for constraint in table.constraints
                )
                has_hierarchy_fk = any(
                    isinstance(constraint, sa.ForeignKeyConstraint)
                    and set(constraint.column_keys) == {"tenant_id", "team_id", "organization_id"}
                    and constraint.referred_table.name == "teams"
                    for constraint in table.constraints
                )
                if not has_check or not has_hierarchy_fk:
                    issues.append(
                        LintIssue("L15", table.name, "team ownership constraints missing")
                    )

    for metadata in controls:
        for name in _cascade_reachable(metadata):
            issues.append(LintIssue("L6", name, "cascade path from tenants"))

    return issues


def assert_clean(controls: list[MetaData], rls_enabled: bool = False) -> None:
    issues = lint_metadata(controls, rls_enabled=rls_enabled)
    if issues:
        raise SchemaLintError([f"{issue.rule} {issue.table}: {issue.message}" for issue in issues])
