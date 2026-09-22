from __future__ import annotations

import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Protocol


class PlatformAudit(Protocol):
    async def record(
        self,
        *,
        action: str,
        tenant_id: uuid.UUID | None,
        actor_id: uuid.UUID | None,
        metadata: Mapping[str, object] | None = None,
    ) -> None: ...


class NullPlatformAudit:
    async def record(
        self,
        *,
        action: str,
        tenant_id: uuid.UUID | None,
        actor_id: uuid.UUID | None,
        metadata: Mapping[str, object] | None = None,
    ) -> None:
        raise RuntimeError("no platform audit sink is configured")


@dataclass
class RecordingPlatformAudit:
    entries: list[dict[str, object]] = field(default_factory=list)

    async def record(
        self,
        *,
        action: str,
        tenant_id: uuid.UUID | None,
        actor_id: uuid.UUID | None,
        metadata: Mapping[str, object] | None = None,
    ) -> None:
        self.entries.append(
            {
                "action": action,
                "tenant_id": tenant_id,
                "actor_id": actor_id,
                "metadata": dict(metadata or {}),
            }
        )
