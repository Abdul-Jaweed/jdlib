import uuid

import pytest
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from jdlib.errors import UnscopedRawSql
from jdlib.persistence.rawsql import RawSqlValidator

TENANT_ID = uuid.UUID("00000000-0000-0000-0000-0000000000aa")
OTHER_ID = uuid.UUID("00000000-0000-0000-0000-0000000000bb")
DIALECT = postgresql.asyncpg.dialect()


@pytest.fixture()
def validator() -> RawSqlValidator:
    return RawSqlValidator(tenant_tables={"invoices": object, "projects": object})


def _compiled(sql: str, **params: object):
    statement = sa.text(sql).bindparams(**{k: sa.bindparam(k) for k in params})
    return RawSqlValidator.compile(statement, DIALECT, params)


def test_select_with_tenant_predicate_passes(validator):
    validator.validate_tenant_bound(
        _compiled(
            "SELECT * FROM invoices WHERE tenant_id = :tenant_id", tenant_id=TENANT_ID
        ),
        TENANT_ID,
    )


def test_select_without_predicate_rejected(validator):
    with pytest.raises(UnscopedRawSql):
        validator.validate_tenant_bound(_compiled("SELECT * FROM invoices"), TENANT_ID)


def test_or_true_rejected(validator):
    with pytest.raises(UnscopedRawSql):
        validator.validate_tenant_bound(
            _compiled(
                "SELECT * FROM invoices WHERE tenant_id = :tenant_id OR TRUE",
                tenant_id=TENANT_ID,
            ),
            TENANT_ID,
        )


def test_wrong_tenant_value_rejected(validator):
    with pytest.raises(UnscopedRawSql):
        validator.validate_tenant_bound(
            _compiled(
                "SELECT * FROM invoices WHERE tenant_id = :tenant_id", tenant_id=OTHER_ID
            ),
            TENANT_ID,
        )


def test_is_distinct_from_predicate_rejected(validator):
    with pytest.raises(UnscopedRawSql):
        validator.validate_tenant_bound(
            _compiled(
                "SELECT * FROM invoices WHERE tenant_id IS DISTINCT FROM :tenant_id",
                tenant_id=TENANT_ID,
            ),
            TENANT_ID,
        )


def test_is_not_distinct_from_predicate_rejected(validator):
    with pytest.raises(UnscopedRawSql):
        validator.validate_tenant_bound(
            _compiled(
                "SELECT * FROM invoices WHERE tenant_id IS NOT DISTINCT FROM :tenant_id",
                tenant_id=TENANT_ID,
            ),
            TENANT_ID,
        )


def test_any_predicate_rejected(validator):
    with pytest.raises(UnscopedRawSql):
        validator.validate_tenant_bound(
            _compiled(
                "SELECT * FROM invoices WHERE tenant_id = ANY(:tenant_id)",
                tenant_id=TENANT_ID,
            ),
            TENANT_ID,
        )


def test_join_requires_predicate_on_every_relation(validator):
    sql = (
        "SELECT * FROM invoices i JOIN projects p ON p.tenant_id = i.tenant_id "
        "WHERE i.tenant_id = :tenant_id"
    )
    with pytest.raises(UnscopedRawSql):
        validator.validate_tenant_bound(_compiled(sql, tenant_id=TENANT_ID), TENANT_ID)
    sql_ok = (
        "SELECT * FROM invoices i JOIN projects p ON p.tenant_id = i.tenant_id "
        "WHERE i.tenant_id = :tenant_id AND p.tenant_id = :tenant_id"
    )
    validator.validate_tenant_bound(_compiled(sql_ok, tenant_id=TENANT_ID), TENANT_ID)


def test_update_and_delete_require_predicate(validator):
    validator.validate_tenant_bound(
        _compiled(
            "UPDATE invoices SET status = :status WHERE tenant_id = :tenant_id",
            status="paid",
            tenant_id=TENANT_ID,
        ),
        TENANT_ID,
    )
    with pytest.raises(UnscopedRawSql):
        validator.validate_tenant_bound(
            _compiled("DELETE FROM invoices"), TENANT_ID
        )


def test_insert_requires_bound_tenant_value(validator):
    validator.validate_tenant_bound(
        _compiled(
            "INSERT INTO invoices (tenant_id, id) VALUES (:tenant_id, :id)",
            tenant_id=TENANT_ID,
            id=uuid.uuid4(),
        ),
        TENANT_ID,
    )
    with pytest.raises(UnscopedRawSql):
        validator.validate_tenant_bound(
            _compiled(
                "INSERT INTO invoices (tenant_id, id) VALUES (:tenant_id, :id)",
                tenant_id=OTHER_ID,
                id=uuid.uuid4(),
            ),
            TENANT_ID,
        )


def test_unknown_relation_and_schema_escape_rejected(validator):
    with pytest.raises(UnscopedRawSql):
        validator.validate_tenant_bound(
            _compiled("SELECT * FROM mystery WHERE tenant_id = :tenant_id", tenant_id=TENANT_ID),
            TENANT_ID,
        )
    with pytest.raises(UnscopedRawSql):
        validator.validate_tenant_bound(
            _compiled(
                "SELECT * FROM other_schema.invoices WHERE tenant_id = :tenant_id",
                tenant_id=TENANT_ID,
            ),
            TENANT_ID,
        )


def test_cte_subquery_and_multi_statement_rejected(validator):
    with pytest.raises(UnscopedRawSql):
        validator.validate_tenant_bound(
            _compiled(
                "WITH x AS (SELECT * FROM invoices) SELECT * FROM x WHERE tenant_id = :tenant_id",
                tenant_id=TENANT_ID,
            ),
            TENANT_ID,
        )
    with pytest.raises(UnscopedRawSql):
        validator.validate_tenant_bound(
            _compiled(
                "SELECT * FROM (SELECT * FROM invoices) s WHERE tenant_id = :tenant_id",
                tenant_id=TENANT_ID,
            ),
            TENANT_ID,
        )
    with pytest.raises(UnscopedRawSql):
        validator.validate_tenant_bound(
            _compiled(
                "SELECT * FROM invoices WHERE tenant_id = :tenant_id; DROP TABLE invoices",
                tenant_id=TENANT_ID,
            ),
            TENANT_ID,
        )


def test_privileged_mode_still_rejects_ddl(validator):
    validator.validate_privileged(_compiled("SELECT * FROM invoices"))
    with pytest.raises(UnscopedRawSql):
        validator.validate_privileged(_compiled("DROP TABLE invoices"))


def test_scalar_subquery_in_target_list_rejected(validator):
    with pytest.raises(UnscopedRawSql):
        validator.validate_tenant_bound(
            _compiled(
                "SELECT (SELECT count(*) FROM projects) FROM invoices "
                "WHERE tenant_id = :tenant_id",
                tenant_id=TENANT_ID,
            ),
            TENANT_ID,
        )


def test_exists_subquery_in_where_rejected(validator):
    with pytest.raises(UnscopedRawSql):
        validator.validate_tenant_bound(
            _compiled(
                "SELECT * FROM invoices WHERE tenant_id = :tenant_id "
                "AND EXISTS (SELECT 1 FROM projects)",
                tenant_id=TENANT_ID,
            ),
            TENANT_ID,
        )


def test_insert_checks_every_values_row(validator):
    validator.validate_tenant_bound(
        _compiled(
            "INSERT INTO invoices (tenant_id, id) VALUES (:tenant_id, :id1), (:tenant_id, :id2)",
            tenant_id=TENANT_ID,
            id1=uuid.uuid4(),
            id2=uuid.uuid4(),
        ),
        TENANT_ID,
    )
    with pytest.raises(UnscopedRawSql):
        validator.validate_tenant_bound(
            _compiled(
                "INSERT INTO invoices (tenant_id, id) VALUES (:tenant_id, :id1), (:other, :id2)",
                tenant_id=TENANT_ID,
                other=OTHER_ID,
                id1=uuid.uuid4(),
                id2=uuid.uuid4(),
            ),
            TENANT_ID,
        )


def test_insert_literal_tenant_value_rejected(validator):
    with pytest.raises(UnscopedRawSql):
        validator.validate_tenant_bound(
            _compiled(
                "INSERT INTO invoices (tenant_id, id) VALUES (:tenant_id, :id1), "
                "('00000000-0000-0000-0000-0000000000bb', :id2)",
                tenant_id=TENANT_ID,
                id1=uuid.uuid4(),
                id2=uuid.uuid4(),
            ),
            TENANT_ID,
        )


def test_update_from_requires_predicate_on_every_relation(validator):
    sql = (
        "UPDATE invoices SET status = :status FROM projects p "
        "WHERE invoices.tenant_id = :tenant_id"
    )
    with pytest.raises(UnscopedRawSql):
        validator.validate_tenant_bound(
            _compiled(sql, status="paid", tenant_id=TENANT_ID), TENANT_ID
        )
    sql_ok = (
        "UPDATE invoices SET status = :status FROM projects p "
        "WHERE invoices.tenant_id = :tenant_id AND p.tenant_id = :tenant_id"
    )
    validator.validate_tenant_bound(
        _compiled(sql_ok, status="paid", tenant_id=TENANT_ID), TENANT_ID
    )


def test_delete_using_requires_predicate_on_every_relation(validator):
    with pytest.raises(UnscopedRawSql):
        validator.validate_tenant_bound(
            _compiled(
                "DELETE FROM invoices USING projects WHERE invoices.tenant_id = :tenant_id",
                tenant_id=TENANT_ID,
            ),
            TENANT_ID,
        )


def test_malformed_sql_raises_unscoped(validator):
    with pytest.raises(UnscopedRawSql):
        validator.validate_tenant_bound(_compiled("SELECT FROM"), TENANT_ID)


def test_missing_bind_parameter_raises_unscoped():
    with pytest.raises(UnscopedRawSql):
        _compiled("SELECT * FROM invoices WHERE tenant_id = :tenant_id")
