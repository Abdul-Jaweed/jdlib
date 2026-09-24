from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field


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
    #: Connection parameters that belong to the target rather than to the caller. A schema is
    #: the reason this exists: asyncpg takes a search_path only as a connection setting, not
    #: from the DSN, and improvising one at the call site would put deployment knowledge in
    #: the query path. Not credential material, so it renders nowhere either - the repr below
    #: is unchanged and says nothing about it.
    server_settings: Mapping[str, str] = field(default_factory=dict)

    def __repr__(self) -> str:
        return (
            f"ConnectionConfig(handle={self.handle!r}, target=[REDACTED], "
            f"credential_version={self.credential_version!r}, tenant_id={self.tenant_id!r})"
        )
