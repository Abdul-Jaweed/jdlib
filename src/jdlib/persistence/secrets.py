from __future__ import annotations

import os
from typing import Protocol


class SecretProvider(Protocol):
    def resolve(self, handle: str) -> str: ...


class MemorySecretProvider:
    def __init__(self, mapping: dict[str, str]) -> None:
        self._mapping = dict(mapping)

    def resolve(self, handle: str) -> str:
        try:
            return self._mapping[handle]
        except KeyError as exc:
            raise KeyError(f"no secret for handle {handle}") from exc


class EnvSecretProvider:
    def __init__(self, prefix: str = "JDLIB_TENANT_DB_") -> None:
        self._prefix = prefix

    def resolve(self, handle: str) -> str:
        key = self._prefix + handle.upper().replace("-", "_")
        value = os.environ.get(key)
        if value is None:
            raise KeyError(f"missing environment variable {key}")
        return value
