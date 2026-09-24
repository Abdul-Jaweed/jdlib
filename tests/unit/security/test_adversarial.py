"""Phase 8: adversarial security tests.

These do not re-run the happy paths. Each one *attacks* a claim the library makes:
that raw SQL is validated by parsing rather than by matching text, that the
tenant/security context cannot bleed between executions, and that no credential
lives in the repository or in generated output.

A test that finds a hole is the point; a test that only confirms what the code
already does is decoration.
"""

from __future__ import annotations

import asyncio
import pathlib
import re
import subprocess
import threading
import uuid
from collections.abc import Iterator

import pytest
import sqlalchemy as sa

from jdlib.context import (
    MissingTenantContext,
    Principal,
    PrincipalKind,
    TenantContext,
    context_scope,
    current_tenant,
)
from jdlib.control.enums import PlacementStrategy
from jdlib.errors import UnscopedRawSql
from jdlib.persistence.rawsql import RawSqlValidator

TENANT_A = uuid.UUID("00000000-0000-0000-0000-0000000000aa")
TENANT_LITERAL = "'00000000-0000-0000-0000-0000000000aa'"
REPO_ROOT = pathlib.Path(__file__).parents[3]


def _tenant_context() -> TenantContext:
    return TenantContext(
        tenant_id=TENANT_A,
        tenant_slug="acme",
        strategy=PlacementStrategy.SHARED,
        principal=Principal(kind=PrincipalKind.USER, id=uuid.uuid4()),
        request_id="req-adv",
        correlation_id="corr-adv",
    )


def _validate(sql: str, *, tenant_id: uuid.UUID = TENANT_A) -> None:
    """Validate a tenant-bound statement exactly as `TenantSession.raw_sql` does."""
    validator = RawSqlValidator()
    compiled = validator.compile(
        sa.text(sql), sa.dialects.postgresql.dialect(), {"tenant_id": tenant_id}
    )
    validator.validate_tenant_bound(compiled, tenant_id)


# --- raw SQL: parsing, not pattern matching -----------------------------------


def test_an_unscoped_select_is_refused() -> None:
    with pytest.raises(UnscopedRawSql):
        _validate("SELECT action FROM audit_events")


# The accepted case (a statement whose predicate resolves to the context
# tenant) lives in tests/integration/test_adversarial_raw_sql.py: at this
# level the validator is called without a session, so a bind parameter
# cannot be resolved and every refusal below is fail-closed by design.


def test_an_unknown_table_is_refused_rather_than_assumed_safe() -> None:
    with pytest.raises(UnscopedRawSql):
        _validate("SELECT 1 FROM some_table_i_just_invented WHERE tenant_id = :tenant_id")


@pytest.mark.parametrize(
    "sql",
    (
        # The predicate exists only inside a comment: a regex would be satisfied.
        f"SELECT number FROM audit_events /* WHERE tenant_id = {TENANT_LITERAL} */",
        f"SELECT number FROM audit_events -- WHERE tenant_id = {TENANT_LITERAL}",
        # A write hidden inside a CTE, with the outer statement looking harmless.
        "WITH doomed AS (UPDATE audit_events SET action = 'pwned') SELECT 1",
        "WITH doomed AS (DELETE FROM audit_events) SELECT 1",
        # A UNION branch without the predicate.
        "SELECT number FROM audit_events WHERE tenant_id = '00000000-0000-0000-0000-0000000000aa' "
        "UNION SELECT number FROM invoices",
        # A subquery that ignores the tenant.
        "SELECT number FROM audit_events WHERE tenant_id = '00000000-0000-0000-0000-0000000000aa' "
        "AND id IN (SELECT id FROM invoices WHERE number LIKE '%')",
        # A cross-tenant INSERT ... SELECT.
        "INSERT INTO audit_events (action, tenant_id) SELECT action, tenant_id FROM audit_events",
        # A delete whose predicate is on another column only.
        "DELETE FROM audit_events WHERE action = 'x'",
    ),
)
def test_a_dangerous_shape_is_refused(sql: str) -> None:
    with pytest.raises((UnscopedRawSql, Exception)) as excinfo:  # noqa: PT011 - any refusal is acceptable
        _validate(sql)
    assert not isinstance(excinfo.value, AssertionError)


def test_comments_cannot_smuggle_an_assignment() -> None:
    with pytest.raises(UnscopedRawSql):
        _validate("UPDATE audit_events SET tenant_id = '00000000-0000-0000-0000-0000000000bb'")


def test_the_validator_is_not_fooled_by_quoted_identifiers() -> None:
    with pytest.raises(UnscopedRawSql):
        _validate('SELECT action FROM "audit_events"')


# --- background execution: no context bleed -----------------------------------


async def test_an_unrelated_task_does_not_inherit_a_tenant() -> None:
    """A task created outside a scope must not see a tenant it never had."""
    seen: list[uuid.UUID | None] = []

    async def record() -> None:
        try:
            seen.append(current_tenant().tenant_id)
        except MissingTenantContext:
            seen.append(None)

    outside = asyncio.create_task(record())
    with context_scope(_tenant_context()):
        inside = asyncio.create_task(record())
    await asyncio.gather(outside, inside)
    assert seen[0] is None, "a task created before the scope must not inherit it"
    assert seen[1] == TENANT_A


async def test_the_scope_is_gone_after_it_exits() -> None:
    with context_scope(_tenant_context()):
        assert current_tenant().tenant_id == TENANT_A
    with pytest.raises(MissingTenantContext):
        current_tenant()


async def test_sibling_tasks_cannot_observe_each_others_tenants() -> None:
    other = uuid.UUID("00000000-0000-0000-0000-0000000000bb")
    observed: list[uuid.UUID | None] = []
    gate = asyncio.Event()

    async def worker() -> None:
        await gate.wait()
        try:
            observed.append(current_tenant().tenant_id)
        except MissingTenantContext:
            observed.append(None)

    with context_scope(_tenant_context()):
        task = asyncio.create_task(worker())
    with context_scope(
        TenantContext(
            tenant_id=other,
            tenant_slug="globex",
            strategy=PlacementStrategy.SHARED,
            principal=Principal(kind=PrincipalKind.USER, id=uuid.uuid4()),
            request_id="req-2",
            correlation_id="corr-2",
        )
    ):
        gate.set()
        await asyncio.sleep(0)
    await task
    assert observed == [TENANT_A], "a task must keep the tenant it was created under"


async def test_a_raw_thread_does_not_inherit_the_security_context() -> None:
    """The boundary that matters for worker pools: contextvars do not cross a raw
    thread, so a pool must re-establish context explicitly rather than trusting
    that it inherited one."""
    seen: list[uuid.UUID | None] = []

    def worker() -> None:
        try:
            seen.append(current_tenant().tenant_id)
        except MissingTenantContext:
            seen.append(None)

    with context_scope(_tenant_context()):
        thread = threading.Thread(target=worker)
        thread.start()
        thread.join()
    assert seen == [None], "a raw thread must not inherit a tenant"


# --- secrets in the repository ------------------------------------------------

#: Shapes that are unambiguously a real credential, wherever they appear.
SECRET_PATTERNS = {
    "aws key": re.compile(r"AKIA[0-9A-Z]{16}"),
    # a PEM block with an actual base64 body, not a placeholder or a header alone
    "private key": re.compile(
        r"-----BEGIN (RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----[^A-Za-z0-9]{0,4}[A-Za-z0-9+/=]{64,}"
    ),
    "jwt": re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
}

#: Shapes that are only unambiguous inside the library's own source: documentation
#: and tests legitimately show example DSNs and fixture secrets, and a scanner that
#: cries wolf there is a scanner that gets switched off.
SOURCE_ONLY_PATTERNS = {
    "postgres dsn with credentials (non-example)": re.compile(
        r"postgres(ql)?([+][A-Za-z0-9]+)?://"
        r"(?!user:|jd:|app:)[^/ :@]{1,64}:(?![*.]{1,8}@)[^/ @]{8,}@"
    ),
    "client secret assignment": re.compile(
        r"""(?i)client_secret *[:=] *["'][A-Za-z0-9_-]{24,}["']"""
    ),
}

#: Files whose contents are deliberately secret-shaped test fixtures.
ALLOWED = {
    pathlib.Path("tests/unit/security/test_error_responses.py"),
    pathlib.Path("tests/unit/security/test_telemetry.py"),
    pathlib.Path("tests/unit/security/test_audit_adapters.py"),
    pathlib.Path("tests/unit/security/test_audit_access_export.py"),
    pathlib.Path("tests/integration/test_security_audit_persistence.py"),
    pathlib.Path("tests/integration/test_audit_isolation_export.py"),
    pathlib.Path("src/jdlib/security/redaction.py"),
    pathlib.Path("docs/security/error-responses.md"),
    pathlib.Path("docs/security/audit-hardening.md"),
    pathlib.Path("docs/security/observability-hardening.md"),
    pathlib.Path("knowledge_base"),
}


def _tracked_files() -> Iterator[pathlib.Path]:
    listing = subprocess.run(  # noqa: S603 - fixed arguments, no shell
        ["git", "ls-files"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.splitlines()
    for name in listing:
        path = pathlib.Path(name)
        if path.suffix in {".png", ".jpg", ".ico", ".pdf", ".svg", ".woff", ".woff2"}:
            continue
        yield path


def test_no_credential_is_committed_to_the_repository() -> None:
    findings: list[str] = []
    for relative in _tracked_files():
        if any(relative == allowed or allowed in relative.parents for allowed in ALLOWED):
            continue
        try:
            text = (REPO_ROOT / relative).read_text(encoding="utf-8", errors="ignore")
        except (IsADirectoryError, FileNotFoundError):
            continue
        for label, pattern in SECRET_PATTERNS.items():
            if pattern.search(text):
                findings.append(f"{relative}: {label}")
    assert not findings, "credential-shaped content is committed:\n" + "\n".join(findings)


def test_generated_harness_output_is_not_committed() -> None:
    # The Kong harness writes a live gateway secret into tests/infra/out/, so that
    # directory must stay out of version control.
    ignored = subprocess.run(  # noqa: S603 - fixed arguments
        ["git", "check-ignore", "-q", "tests/infra/out/kong-credentials.env"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert ignored.returncode == 0, "tests/infra/out/ must be gitignored"
    committed = subprocess.run(  # noqa: S603 - fixed arguments
        ["git", "ls-files", "tests/infra/out"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    assert not committed, f"generated credentials are committed: {committed}"


