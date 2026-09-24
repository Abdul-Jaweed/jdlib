from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class SecretVersion:
    """An opaque token identifying one generation of a secret.

    Compared by equality; consumers use inequality to detect that a credential changed and a
    pooled connection must be rebuilt, which the tenant-lifecycle design requires.
    """

    value: str

    def __post_init__(self) -> None:
        if not self.value:
            raise ValueError("a secret version must not be empty")

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class SecretRef:
    """A reference to a secret. It carries no value, and it cannot render one.

    ``version`` is optional: omit it to resolve whatever is current, pin it to fail closed
    when the secret has been rotated away.
    """

    handle: str
    version: SecretVersion | None = None

    def __post_init__(self) -> None:
        if not self.handle:
            raise ValueError("a secret reference must name a handle")

    def __str__(self) -> str:
        if self.version is None:
            return self.handle
        return f"{self.handle}@{self.version}"


@dataclass(frozen=True, slots=True)
class ResolvedSecret:
    """A resolved value plus the version it came from.

    The value is absent from ``repr``: a resolved secret is the object most likely to be
    logged by accident, so the accident renders metadata only.
    """

    ref: SecretRef
    version: SecretVersion
    value: str

    def __repr__(self) -> str:
        return f"ResolvedSecret(ref={self.ref!r}, version={self.version!r}, value=[REDACTED])"
