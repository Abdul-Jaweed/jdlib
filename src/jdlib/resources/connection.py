from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ConnectionConfig:
    """A hydrated target: what to connect to, and which credential version produced it.

    ``target`` is credential material, so this type renders without it. Everything that logs,
    audits or traces a connection therefore cannot leak the secret by accident - which is the
    property the credential-leakage test asserts rather than trusts.
    """

    handle: str
    target: str
    credential_version: str
    tenant_id: str

    def __repr__(self) -> str:
        return (
            f"ConnectionConfig(handle={self.handle!r}, target=[REDACTED], "
            f"credential_version={self.credential_version!r}, tenant_id={self.tenant_id!r})"
        )
