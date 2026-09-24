from __future__ import annotations

from typing import Final

from jdlib.credentials.errors import (
    CredentialUnavailableError,
    CredentialVersionRetiredError,
)
from jdlib.credentials.refs import ResolvedSecret, SecretRef, SecretVersion
from jdlib.persistence.secrets import SecretProvider
from jdlib.security.tracing import TracerLike, security_span

INITIAL_VERSION: Final = SecretVersion("1")


class VersionedSecretProvider:
    """Wrap any secret provider to give its secrets observable, refusable versions.

    Rotation is detected, not performed: this provider does not talk to a secret manager, it
    tracks which generation it last handed out so that consumers can see a change and rebuild,
    and a caller holding a retired version is refused rather than quietly served a value it
    did not ask for.

    ``resolve`` accepts a ``SecretRef`` or a bare handle string, so it still composes with code
    written against the existing ``SecretProvider`` protocol.
    """

    def __init__(self, inner: SecretProvider, *, tracer: TracerLike | None = None) -> None:
        self._inner = inner
        self._tracer = tracer
        self._current: dict[str, SecretVersion] = {}
        self._retired: dict[str, set[SecretVersion]] = {}
        self._pin: dict[tuple[str, SecretVersion], str] = {}

    def resolve(self, ref: SecretRef | str) -> ResolvedSecret:
        with security_span(
            self._tracer, "credentials.resolve",
            attributes={"security.operation": "credentials.resolve"},
        ) as span:
            try:
                resolved = self._resolve_inner(ref)
            except Exception:
                span.set_attribute("security.result", "refused")
                raise
            span.set_attribute("security.result", "resolved")
            return resolved

    def _resolve_inner(self, ref: SecretRef | str) -> ResolvedSecret:
        if isinstance(ref, str):
            ref = SecretRef(handle=ref)

        version = self._current.get(ref.handle)
        if version is None:
            version = INITIAL_VERSION
            self._current[ref.handle] = version

        if ref.version is not None:
            if ref.version in self._retired.get(ref.handle, set()):
                raise CredentialVersionRetiredError(
                    f"secret version {ref.version} for handle {ref.handle} has been rotated "
                    "away; resolve the current version and rebuild"
                )
            if ref.version != version:
                raise CredentialUnavailableError(
                    f"secret version {ref.version} for handle {ref.handle} is not the current "
                    f"version {version}"
                )
            pinned = self._pin.get((ref.handle, ref.version))
            if pinned is not None:
                return ResolvedSecret(ref=ref, version=version, value=pinned)

        value = self._read(ref.handle)
        if ref.version is not None:
            self._pin[(ref.handle, ref.version)] = value
        return ResolvedSecret(ref=ref, version=version, value=value)

    def _read(self, handle: str) -> str:
        try:
            return self._inner.resolve(handle)
        except CredentialUnavailableError:
            raise
        except Exception as exc:
            raise CredentialUnavailableError(
                f"could not resolve credential for handle {handle}"
            ) from exc

    def current_version(self, handle: str) -> SecretVersion | None:
        """The version currently served for a handle, establishing it on first ask.

        Laziness here would be wrong for the consumer this exists for: a caller deciding
        whether a cached connection target is still valid must be able to ask the version
        *before* resolving. Reading the inner provider is the cheap half of that decision -
        it is connecting that is expensive. A handle nobody holds still reports None, and
        callers fail closed on that.
        """
        known = self._current.get(handle)
        if known is not None:
            return known
        try:
            self._read(handle)
        except CredentialUnavailableError:
            return None
        self._current.setdefault(handle, INITIAL_VERSION)
        return self._current[handle]

    def rotate(self, handle: str, *, new_value: str, version: str) -> SecretVersion:
        """Declare a new generation. The previous one stops being served."""
        previous = self._current.get(handle)
        if previous is None:
            # Rotating a handle that has never been resolved is fine if the inner provider
            # actually holds it: establish the version rather than demanding a prior read.
            # A handle nobody holds still fails closed, below.
            try:
                self._inner.resolve(handle)
            except Exception as exc:
                raise CredentialUnavailableError(
                    f"cannot rotate handle {handle}: no provider holds a credential for it"
                ) from exc
            previous = INITIAL_VERSION
            self._current[handle] = previous

        new = SecretVersion(version)
        self._retired.setdefault(handle, set()).add(previous)
        self._current[handle] = new
        self._pin[(handle, new)] = new_value
        self._install(handle, new_value)
        return new

    def _install(self, handle: str, new_value: str) -> None:
        """Let the inner provider serve the new value when it can hold one."""
        mapping = getattr(self._inner, "_mapping", None)
        if isinstance(mapping, dict):
            mapping[handle] = new_value
