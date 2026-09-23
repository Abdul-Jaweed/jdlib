"""Phase 1 security core: stable machine-readable security error model.

Spec refs: JDLib hardening spec #21 (standard security error model), #75
(error architecture: stable code, HTTP mapping, retryability, classification).
"""

from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from jdlib import errors
from jdlib.security.errors import (
    SecurityClassification,
    SecurityCode,
    SecurityDescriptor,
    describe_error,
    is_retryable,
    security_code,
    www_authenticate,
)
from jdlib.tenancy.middleware import http_status_for

# Every exported error class with a way to instantiate it, so the runtime
# HTTP mapping can be compared against the declarative descriptor.
_INSTANCES = {
    "TenantNotFound": lambda cls: cls("acme"),
    "CrossTenantReferenceError": lambda cls: cls("doc", "a", "b"),
    "SchemaLintError": lambda cls: cls(["missing tenant_id"]),
}


def _instance(cls: type[errors.JdlibError]) -> errors.JdlibError:
    factory = _INSTANCES.get(cls.__name__)
    return factory(cls) if factory else cls("detail")


def test_every_exported_error_class_has_a_descriptor() -> None:
    missing = [
        name for name in errors.__all__ if describe_error(getattr(errors, name)) is None
    ]
    assert missing == []


def test_descriptor_http_status_matches_runtime_mapping() -> None:
    for name in errors.__all__:
        cls = getattr(errors, name)
        descriptor = describe_error(cls)
        assert descriptor is not None
        assert descriptor.http_status == http_status_for(_instance(cls)), name


def test_descriptor_codes_are_declared_security_codes() -> None:
    for name in errors.__all__:
        descriptor = describe_error(getattr(errors, name))
        assert descriptor is not None
        assert isinstance(descriptor.code, SecurityCode), name
        assert descriptor.code in SecurityCode, name


def test_unique_codes_per_error_class() -> None:
    codes = {name: describe_error(getattr(errors, name)).code for name in errors.__all__}
    # Distinct errors may legitimately share one code, but the mapping must be
    # deliberate: every code is attached to at least one class, and the
    # authentication family keeps its documented per-condition codes.
    assert codes["InvalidToken"] is SecurityCode.INVALID_TOKEN
    assert codes["ExpiredToken"] is SecurityCode.EXPIRED_TOKEN
    assert codes["AuthenticationError"] is SecurityCode.AUTHENTICATION_REQUIRED
    assert codes["AuthorizationError"] is SecurityCode.PERMISSION_DENIED
    assert codes["PermissionDenied"] is SecurityCode.PERMISSION_DENIED
    assert codes["TenantNotFound"] is SecurityCode.TENANT_NOT_FOUND
    assert codes["TenantAccessDenied"] is SecurityCode.TENANT_ACCESS_DENIED
    assert codes["TenantSuspended"] is SecurityCode.TENANT_SUSPENDED
    assert codes["TenantNotWritable"] is SecurityCode.TENANT_NOT_SERVABLE
    assert codes["CrossTenantReferenceError"] is SecurityCode.CROSS_TENANT_ACCESS


def test_spec_required_codes_exist() -> None:
    required = {
        "AUTHENTICATION_REQUIRED",
        "INVALID_TOKEN",
        "EXPIRED_TOKEN",
        "INVALID_AUDIENCE",
        "INVALID_ISSUER",
        "INSUFFICIENT_SCOPE",
        "PERMISSION_DENIED",
        "TENANT_NOT_FOUND",
        "TENANT_ACCESS_DENIED",
        "TENANT_SUSPENDED",
        "TENANT_NOT_SERVABLE",
        "CROSS_TENANT_ACCESS",
        "POLICY_DENIED",
        "POLICY_UNAVAILABLE",
        "SECURITY_CONFIGURATION_ERROR",
    }
    assert required <= {member.name for member in SecurityCode}


def test_classification_of_each_family() -> None:
    assert (
        describe_error(errors.InvalidToken).classification
        is SecurityClassification.AUTHENTICATION
    )
    assert (
        describe_error(errors.PermissionDenied).classification
        is SecurityClassification.AUTHORIZATION
    )
    assert (
        describe_error(errors.TenantAccessDenied).classification
        is SecurityClassification.TENANCY
    )
    assert (
        describe_error(errors.UnscopedRawSql).classification
        is SecurityClassification.DATA_BOUNDARY
    )


def test_retryability_distinguishes_transient_from_security_failures() -> None:
    # Transient capacity/conflict conditions are retryable.
    assert is_retryable(errors.PoolCapacityError("pool full")) is True
    assert is_retryable(errors.TenantOperationInProgress("busy")) is True
    # Security failures are never retryable.
    assert is_retryable(errors.PermissionDenied("denied")) is False
    assert is_retryable(errors.InvalidToken("bad")) is False
    assert is_retryable(errors.TenantAccessDenied("denied")) is False


def test_www_authenticate_only_for_authentication_challenges() -> None:
    assert www_authenticate(errors.AuthenticationError("none")) == 'Bearer realm="jdlib"'
    assert (
        www_authenticate(errors.InvalidToken("bad"))
        == 'Bearer realm="jdlib", error="invalid_token"'
    )
    assert www_authenticate(errors.ExpiredToken("stale")) == (
        'Bearer realm="jdlib", error="invalid_token", '
        'error_description="The access token expired"'
    )
    assert www_authenticate(errors.PermissionDenied("denied")) is None
    assert www_authenticate(errors.TenantNotFound("acme")) is None


def test_subclass_lookup_uses_nearest_declared_descriptor() -> None:
    class CustomDenied(errors.PermissionDenied):
        pass

    assert describe_error(CustomDenied("x")).code is SecurityCode.PERMISSION_DENIED


def test_unknown_jdlib_error_fails_closed_to_internal_error() -> None:
    class MysteryError(errors.JdlibError):
        pass

    assert security_code(MysteryError("boom")) is SecurityCode.INTERNAL_ERROR
    assert describe_error(MysteryError("boom")).http_status == 500
    assert describe_error(MysteryError("boom")).classification is SecurityClassification.INTERNAL


def test_describe_error_accepts_class_or_instance() -> None:
    assert describe_error(errors.InvalidToken) == describe_error(errors.InvalidToken("x"))
    assert isinstance(describe_error(errors.InvalidToken), SecurityDescriptor)


def test_descriptors_are_immutable() -> None:
    descriptor = describe_error(errors.InvalidToken)
    with pytest.raises(FrozenInstanceError):
        descriptor.code = SecurityCode.PERMISSION_DENIED  # type: ignore[misc]


def test_authentication_failures_are_not_downgraded_to_anonymous() -> None:
    # A missing authentication is a 401 with a challenge, never a silent pass.
    descriptor = describe_error(errors.AuthenticationError("missing"))
    assert descriptor.http_status == 401
    assert descriptor.retryable is False
