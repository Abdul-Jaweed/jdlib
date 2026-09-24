"""Credential references and rotation — the ADR-2 guard, tested before it exists.

Phase 2 of the successor roadmap. The archived system's worst defect was serialising fully
decrypted credential documents into a shared cache and logging them at INFO, so the properties
this file pins are the ones that make that impossible here:

* a reference carries **no value**, and its repr cannot leak one;
* resolution failure is a structured, fail-closed error that names the handle, not the value;
* rotation produces a **new version** and the retired version is refused rather than silently
  served — the design documents require pool rebuilds on credential-version change, which is
  only possible if the version is observable and the old one stops working;
* composition resolves in declared order and never degrades to a weaker provider;
* the existing `SecretProvider` protocol is untouched, so `MemorySecretProvider` and
  `EnvSecretProvider` keep working with no change (ADR-4: additive by construction).
"""

from __future__ import annotations

import logging

import pytest

from jdlib.persistence.secrets import EnvSecretProvider, MemorySecretProvider

# A value that is not a credential-shaped fixture: secret scanners flag realistic-looking
# tokens even in tests, and a redaction test does not need one to prove the property.
SENTINEL = "plain-text-that-must-never-be-echoed"


def test_memory_and_env_providers_still_satisfy_the_existing_protocol() -> None:
    """The protocol is not being changed; today's implementations must be unaffected.

    Asserted structurally: ``SecretProvider`` is not ``@runtime_checkable``, so isinstance()
    is not available (and adding that decorator would itself be a change to the protocol).
    """
    import inspect

    for provider in (MemorySecretProvider({"h": SENTINEL}), EnvSecretProvider()):
        resolve = getattr(provider, "resolve", None)
        assert callable(resolve), type(provider).__name__
        parameters = list(inspect.signature(resolve).parameters)
        assert parameters[:1] == ["handle"], type(provider).__name__


class TestSecretRef:
    def test_reference_carries_no_value(self) -> None:
        from jdlib.credentials.refs import SecretRef

        ref = SecretRef(handle="db-tenant-acme")

        assert ref.handle == "db-tenant-acme"
        assert ref.version is None
        assert SENTINEL not in repr(ref)

    def test_repr_is_stable_and_value_free_even_when_a_version_is_pinned(self) -> None:
        from jdlib.credentials.refs import SecretRef, SecretVersion

        ref = SecretRef(handle="db-tenant-acme", version=SecretVersion("v3"))

        assert "db-tenant-acme" in repr(ref)
        assert "v3" in repr(ref)
        assert SENTINEL not in repr(ref)

    def test_reference_is_immutable_and_hashable(self) -> None:
        from dataclasses import FrozenInstanceError

        from jdlib.credentials.refs import SecretRef

        ref = SecretRef(handle="h")
        assert hash(ref) == hash(SecretRef(handle="h"))
        with pytest.raises(FrozenInstanceError):
            ref.handle = "other"  # type: ignore[misc]

    def test_refuses_an_empty_handle(self) -> None:
        from jdlib.credentials.refs import SecretRef

        with pytest.raises(ValueError):
            SecretRef(handle="")


class TestFailClosedResolution:
    def test_missing_handle_raises_a_structured_error_naming_the_handle_only(self) -> None:
        from jdlib.credentials.errors import CredentialUnavailableError
        from jdlib.credentials.refs import SecretRef
        from jdlib.credentials.rotation import VersionedSecretProvider

        provider = VersionedSecretProvider(MemorySecretProvider({}))

        with pytest.raises(CredentialUnavailableError) as caught:
            provider.resolve(SecretRef(handle="db-tenant-acme"))

        message = str(caught.value)
        assert "db-tenant-acme" in message
        assert SENTINEL not in message
        assert caught.value.__cause__ is not None, "the underlying cause must be preserved"

    def test_the_error_is_a_jdlib_error_so_callers_keep_one_handling_path(self) -> None:
        from jdlib.credentials.errors import CredentialUnavailableError
        from jdlib.errors import JdlibError

        assert issubclass(CredentialUnavailableError, JdlibError)


class TestRotation:
    def test_rotation_advances_the_version_and_serves_the_new_value(self) -> None:
        from jdlib.credentials.refs import SecretRef
        from jdlib.credentials.rotation import VersionedSecretProvider

        provider = VersionedSecretProvider(MemorySecretProvider({"h": "first"}))

        first = provider.resolve(SecretRef(handle="h"))
        assert first.value == "first"

        provider.rotate("h", new_value="second", version="2")

        assert provider.resolve(SecretRef(handle="h")).value == "second"
        assert provider.current_version("h") is not None

    def test_a_retired_version_is_refused_rather_than_silently_served(self) -> None:
        """The design documents rebuild pools on version change; that needs a hard refusal."""
        from jdlib.credentials.errors import CredentialUnavailableError
        from jdlib.credentials.refs import SecretRef
        from jdlib.credentials.rotation import VersionedSecretProvider

        provider = VersionedSecretProvider(MemorySecretProvider({"h": "first"}))
        provider.resolve(SecretRef(handle="h"))
        old_version = provider.current_version("h")
        provider.rotate("h", new_value="second", version="2")

        with pytest.raises(CredentialUnavailableError):
            provider.resolve(SecretRef(handle="h", version=old_version))

    def test_pinning_the_current_version_resolves(self) -> None:
        from jdlib.credentials.refs import SecretRef
        from jdlib.credentials.rotation import VersionedSecretProvider

        provider = VersionedSecretProvider(MemorySecretProvider({"h": "value"}))
        pinned = SecretRef(handle="h", version=provider.current_version("h"))

        assert provider.resolve(pinned).value == "value"

    def test_rotating_an_unknown_handle_fails_closed(self) -> None:
        from jdlib.credentials.errors import CredentialUnavailableError
        from jdlib.credentials.rotation import VersionedSecretProvider

        provider = VersionedSecretProvider(MemorySecretProvider({}))

        with pytest.raises(CredentialUnavailableError):
            provider.rotate("absent", new_value="x", version="1")

    def test_a_version_is_reported_so_consumers_can_detect_change(self) -> None:
        from jdlib.credentials.refs import SecretRef
        from jdlib.credentials.rotation import VersionedSecretProvider

        provider = VersionedSecretProvider(MemorySecretProvider({"h": "v"}))
        provider.resolve(SecretRef(handle="h"))
        before = provider.current_version("h")
        provider.rotate("h", new_value="v2", version="2")

        assert provider.current_version("h") != before


class TestComposition:
    def test_composition_resolves_in_declared_order(self) -> None:
        from jdlib.credentials.composite import CompositeSecretProvider
        from jdlib.credentials.refs import SecretRef
        from jdlib.credentials.rotation import VersionedSecretProvider

        provider = CompositeSecretProvider(
            [MemorySecretProvider({"h": "from-first"}), MemorySecretProvider({"h": "from-second"})]
        )
        wrapped = VersionedSecretProvider(provider)

        assert wrapped.resolve(SecretRef(handle="h")).value == "from-first"

    def test_composition_falls_through_only_on_absence_never_on_failure(self) -> None:
        """A provider that raises for a reason other than absence must not be masked."""
        from jdlib.credentials.composite import CompositeSecretProvider
        from jdlib.credentials.errors import CredentialUnavailableError

        class _Broken:
            def resolve(self, handle: str) -> str:
                raise RuntimeError("backend unavailable")

        provider = CompositeSecretProvider([_Broken(), MemorySecretProvider({"h": "fallback"})])

        with pytest.raises(CredentialUnavailableError):
            provider.resolve("h")

    def test_composition_reports_absence_when_no_provider_has_the_handle(self) -> None:
        from jdlib.credentials.composite import CompositeSecretProvider
        from jdlib.credentials.errors import CredentialUnavailableError

        provider = CompositeSecretProvider([MemorySecretProvider({})])

        with pytest.raises(CredentialUnavailableError):
            provider.resolve("absent")


class TestNoLeakage:
    def test_a_resolved_value_never_reaches_a_log_record(self, caplog) -> None:
        from jdlib.credentials.refs import SecretRef
        from jdlib.credentials.rotation import VersionedSecretProvider

        provider = VersionedSecretProvider(MemorySecretProvider({"h": SENTINEL}))

        with caplog.at_level(logging.DEBUG):
            resolved = provider.resolve(SecretRef(handle="h"))

        assert resolved.value == SENTINEL
        assert SENTINEL not in caplog.text

    def test_a_resolved_value_does_not_appear_in_the_resolution_object_repr(self) -> None:
        from jdlib.credentials.refs import SecretRef
        from jdlib.credentials.rotation import VersionedSecretProvider

        provider = VersionedSecretProvider(MemorySecretProvider({"h": SENTINEL}))
        resolved = provider.resolve(SecretRef(handle="h"))

        assert SENTINEL not in repr(resolved)

    def test_the_redaction_helper_masks_a_credential_shaped_value(self) -> None:
        """One helper, used by every caller that must render a value's presence."""
        from jdlib.credentials.redaction import redact

        assert redact(SENTINEL) == "[REDACTED]"
        assert redact("") == "[REDACTED]"
        assert redact(None) == "[REDACTED]"
