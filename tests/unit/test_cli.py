from __future__ import annotations

import pytest
import sqlalchemy as sa

testing = pytest.importorskip("typer.testing")

from jdlib.integrations import cli  # noqa: E402
from jdlib.integrations.cli import app  # noqa: E402


def _invoke(*args: str):
    return testing.CliRunner().invoke(app, list(args))


def test_help_lists_every_command_group():
    result = _invoke("--help")
    assert result.exit_code == 0
    for group in ("tenant", "db", "rls", "schema"):
        assert group in result.output


def test_schema_lint_exits_zero_on_framework_metadata():
    result = _invoke("schema", "lint")
    assert result.exit_code == 0, result.output
    assert "clean" in result.output


def test_rls_help_lists_install_and_verify():
    result = _invoke("rls", "--help")
    assert result.exit_code == 0
    assert "install" in result.output
    assert "verify" in result.output


def test_command_without_database_url_fails_cleanly(monkeypatch):
    monkeypatch.delenv("JDLIB_CONTROL_DSN", raising=False)
    result = _invoke("tenant", "list")
    assert result.exit_code != 0
    assert "JDLIB_CONTROL_DSN" in result.output
    assert "Traceback" not in result.output


def test_database_error_fails_cleanly(monkeypatch):
    class _Runner:
        def __init__(self, database_url: str) -> None: ...

        def upgrade_control(self, revision: str = "head") -> None:
            raise sa.exc.SQLAlchemyError("connection lost")

    monkeypatch.setattr(cli, "MigrationRunner", _Runner)
    result = _invoke("db", "upgrade-control", "--database-url", "postgresql://example/db")
    assert result.exit_code != 0
    assert "connection lost" in result.output
    assert "Traceback" not in result.output
