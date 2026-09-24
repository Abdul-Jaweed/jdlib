from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True, slots=True)
class StoredObject:
    """A confirmed write: the key as stored, its size, and the store's entity tag."""

    key: str
    size: int
    etag: str


@dataclass(frozen=True, slots=True)
class ObjectMetadata:
    """What the store knows about an object without transferring its body."""

    key: str
    size: int
    etag: str
    content_type: str | None = None
    last_modified: datetime | None = None
