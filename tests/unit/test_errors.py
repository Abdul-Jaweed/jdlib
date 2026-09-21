from jdlib import errors


def test_all_errors_derive_from_jdlib_error():
    for name in errors.__all__:
        cls = getattr(errors, name)
        assert issubclass(cls, errors.JdlibError)


def test_expected_error_names_exist():
    expected = {
        "MissingTenantContext",
        "TenantNotFound",
        "TenantAccessDenied",
        "TenantSuspended",
        "TenantNotWritable",
        "CrossTenantReferenceError",
        "UnscopedBulkOperation",
        "InvalidReference",
        "InvalidResourcePermission",
        "UnknownResourceType",
        "UnknownPermission",
        "RoleScopeMismatch",
        "AuthenticationError",
        "InvalidToken",
        "ExpiredToken",
        "UnknownPrincipal",
        "AuthorizationError",
        "PermissionDenied",
        "RoleEscalationBlocked",
        "StrategyCapabilityError",
        "PoolCapacityError",
        "TenantOperationInProgress",
        "RelocationPhaseError",
        "UnscopedRawSql",
        "SchemaLintError",
        "ProvisioningError",
        "MigrationError",
    }
    assert expected == set(errors.__all__)


def test_error_messages_include_context():
    err = errors.CrossTenantReferenceError("invoices.project_id", "tenant A", "tenant B")
    assert "invoices.project_id" in str(err)
    assert "tenant A" in str(err)
    assert "tenant B" in str(err)
